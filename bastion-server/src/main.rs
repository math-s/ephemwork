//! Bastion control plane: a tiny HTTP server that maintains the (user, service)
//! -> remote_port map for active developer tunnels and persists it across
//! restarts. The nginx header router (commit 9) reads its snapshot.
//!
//! Listens on `127.0.0.1:8443` by default so it's only reachable through the
//! laptop's SSM port forward; the bastion's security group blocks it from the
//! public internet.

mod handlers;
mod http;
mod nginx;
mod registry;

use anyhow::{Context, Result};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use crate::handlers::{route, MutationListener, NoopListener};
use crate::http::{read_request, write_response, RequestError};
use crate::nginx::{NginxReloader, ReloadCommand};
use crate::registry::{default_registry_path, Registry};

const DEFAULT_BIND: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8443);
const DEFAULT_NGINX_CONFIG: &str = "/etc/nginx/conf.d/ephemwork.conf";

/// Inputs the connection handler needs that don't change across requests.
#[derive(Clone)]
struct ServerConfig {
    persist_path: PathBuf,
    nginx_config: PathBuf,
    nginx_reload: ReloadCommand,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::try_init().ok();
    let addr = std::env::var("EPHEMWORK_BIND")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_BIND);
    let registry_path = default_registry_path();
    let nginx_config = std::env::var("EPHEMWORK_NGINX_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_NGINX_CONFIG));
    let nginx_reload = match std::env::var("EPHEMWORK_NGINX_RELOAD") {
        Ok(cmd) if !cmd.trim().is_empty() => ReloadCommand::Custom(cmd),
        _ => ReloadCommand::None,
    };

    let registry = Registry::load(&registry_path)
        .with_context(|| format!("loading registry from {}", registry_path.display()))?;

    let cfg = ServerConfig {
        persist_path: registry_path.clone(),
        nginx_config: nginx_config.clone(),
        nginx_reload: nginx_reload.clone(),
    };

    tracing::info!(
        bind = %addr,
        registry = %registry_path.display(),
        nginx_config = %nginx_config.display(),
        nginx_reload = ?nginx_reload,
        sessions = registry.len(),
        "bastion control plane starting"
    );

    // On startup, if there are existing sessions, render nginx so the active
    // map is correct after a control-plane restart. With no sessions, the
    // user-data stub remains until the first /register fires.
    if !registry.is_empty() {
        let mut listener = composite_listener(&cfg);
        listener.on_change(&registry);
    }

    serve(addr, Arc::new(Mutex::new(registry)), cfg)
}

/// Run the accept loop. Splitting it out lets integration tests drive the
/// server with arbitrary registries and listeners.
fn serve(addr: SocketAddr, registry: Arc<Mutex<Registry>>, cfg: ServerConfig) -> Result<()> {
    let listener = TcpListener::bind(addr).with_context(|| format!("binding {addr}"))?;
    loop {
        let (stream, _peer) = listener.accept().context("accept")?;
        let registry_clone = registry.clone();
        let cfg_clone = cfg.clone();
        std::thread::spawn(move || {
            if let Err(e) = handle_connection(stream, registry_clone, cfg_clone) {
                tracing::warn!(?e, "connection handler failed");
            }
        });
    }
}

fn handle_connection(
    mut stream: TcpStream,
    registry: Arc<Mutex<Registry>>,
    cfg: ServerConfig,
) -> Result<()> {
    let request = match read_request(&mut stream) {
        Ok(req) => req,
        Err(RequestError::EmptyConnection) => {
            // Port scanner / TCP-only health check / etc. Silent — these
            // are common background noise on a public-ish ALB target.
            return Ok(());
        }
        Err(e) => {
            tracing::warn!(%e, "rejecting malformed connection");
            return Ok(());
        }
    };
    let mut listener = composite_listener(&cfg);
    let response = {
        let mut reg = registry.lock().expect("registry mutex poisoned");
        route(&request, &mut reg, &mut listener)
    };
    write_response(&mut stream, &response)?;
    Ok(())
}

fn composite_listener(cfg: &ServerConfig) -> CompositeListener {
    CompositeListener {
        persist: PersistOnChange::new(cfg.persist_path.clone()),
        nginx: NginxReloader::new(cfg.nginx_config.clone(), cfg.nginx_reload.clone()),
    }
}

/// Fans `on_change` out to every listener. Order: persist first (cheap, makes
/// crash recovery correct) then nginx (slower, may shell out). If persist
/// fails the next call will retry; if nginx fails the new mapping is not yet
/// live, but the registry is still consistent on disk.
struct CompositeListener {
    persist: PersistOnChange,
    nginx: NginxReloader,
}

impl MutationListener for CompositeListener {
    fn on_change(&mut self, registry: &Registry) {
        self.persist.on_change(registry);
        self.nginx.on_change(registry);
    }
}

/// `MutationListener` that snapshots the registry to disk after every change.
/// Failures are logged so a transient disk error doesn't take the bastion down,
/// but they do mean the next restart could lose entries — acceptable because
/// the laptop will re-register on its next `up`.
pub struct PersistOnChange {
    path: PathBuf,
}

impl PersistOnChange {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl MutationListener for PersistOnChange {
    fn on_change(&mut self, registry: &Registry) {
        if let Err(e) = registry.save(&self.path) {
            tracing::warn!(?e, path = %self.path.display(), "persisting registry failed");
        }
    }
}

// Keep NoopListener exported for tests that don't care about persistence.
#[allow(dead_code)]
fn _link_noop() -> NoopListener {
    NoopListener
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::PortRange;
    use ephemwork_common::{RegisterRequest, RegisterResponse};
    use std::io::{Read, Write};
    use std::time::Duration;
    use tempfile::tempdir;

    fn start_test_server() -> (SocketAddr, std::path::PathBuf, std::thread::JoinHandle<()>) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("registry.json");
        let nginx_path = dir.path().join("nginx.conf");
        // Leak the tempdir so it lives for the duration of the test thread.
        std::mem::forget(dir);

        let cfg = ServerConfig {
            persist_path: path.clone(),
            nginx_config: nginx_path,
            nginx_reload: ReloadCommand::None,
        };

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let registry = Arc::new(Mutex::new(Registry::with_range(PortRange {
            start: 10_000,
            end: 10_010,
        })));
        let cfg_clone = cfg.clone();
        let handle = std::thread::spawn(move || {
            // Single-shot accept loop: handle a couple of connections then exit.
            for _ in 0..3 {
                if let Ok((stream, _)) = listener.accept() {
                    let r = registry.clone();
                    let c = cfg_clone.clone();
                    std::thread::spawn(move || {
                        let _ = handle_connection(stream, r, c);
                    });
                }
            }
        });
        (addr, path, handle)
    }

    fn post_json(addr: SocketAddr, path: &str, body: &[u8]) -> (u16, Vec<u8>) {
        let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let req = format!(
            "POST {path} HTTP/1.0\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        s.write_all(req.as_bytes()).unwrap();
        s.write_all(body).unwrap();
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).unwrap();
        let split = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
        let head = std::str::from_utf8(&buf[..split]).unwrap();
        let status: u16 = head
            .lines()
            .next()
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        (status, buf[split + 4..].to_vec())
    }

    #[test]
    fn end_to_end_register_then_persist_and_render_nginx() {
        let (addr, path, _) = start_test_server();

        let body = serde_json::to_vec(&RegisterRequest {
            user: "matheus".into(),
            service: "api".into(),
        })
        .unwrap();
        let (status, body) = post_json(addr, "/register", &body);
        assert_eq!(status, 200);
        let resp: RegisterResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(resp.remote_port, 10_000);

        // Persistence check: load the file we configured the listener to write to.
        // Give the persistence thread a moment to flush.
        std::thread::sleep(Duration::from_millis(150));
        let reloaded = Registry::load(&path).unwrap();
        assert_eq!(reloaded.len(), 1);

        // Nginx-render check: the test ServerConfig points at a file in the
        // same temp dir as the registry, so rendering produces it alongside.
        let nginx_path = path
            .parent()
            .unwrap()
            .join("nginx.conf");
        let rendered = std::fs::read_to_string(&nginx_path).expect("nginx config rendered");
        assert!(rendered.contains("matheus:api"), "rendered config should map the registered key, got:\n{rendered}");
        assert!(rendered.contains("127.0.0.1:10000"), "rendered config should target the allocated port:\n{rendered}");
    }
}
