//! Bastion control plane: a tiny HTTP server that maintains the (user, service)
//! -> remote_port map for active developer tunnels and persists it across
//! restarts. The nginx header router (commit 9) reads its snapshot.
//!
//! Listens on `127.0.0.1:8443` by default so it's only reachable through the
//! laptop's SSM port forward; the bastion's security group blocks it from the
//! public internet.

mod handlers;
mod http;
mod registry;

use anyhow::{Context, Result};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use crate::handlers::{route, MutationListener, NoopListener};
use crate::http::{read_request, write_response};
use crate::registry::{default_registry_path, Registry};

const DEFAULT_BIND: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8443);

fn main() -> Result<()> {
    tracing_subscriber::fmt::try_init().ok();
    let addr = std::env::var("EPHEMWORK_BIND")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_BIND);
    let registry_path = default_registry_path();
    let registry = Registry::load(&registry_path)
        .with_context(|| format!("loading registry from {}", registry_path.display()))?;
    tracing::info!(
        bind = %addr,
        registry = %registry_path.display(),
        sessions = registry.len(),
        "bastion control plane starting"
    );
    serve(addr, Arc::new(Mutex::new(registry)), registry_path)
}

/// Run the accept loop. Splitting it out lets integration tests drive the
/// server with arbitrary registries and listeners.
pub fn serve(addr: SocketAddr, registry: Arc<Mutex<Registry>>, persist_path: PathBuf) -> Result<()> {
    let listener = TcpListener::bind(addr).with_context(|| format!("binding {addr}"))?;
    loop {
        let (stream, _peer) = listener.accept().context("accept")?;
        let registry_clone = registry.clone();
        let persist_path_clone = persist_path.clone();
        std::thread::spawn(move || {
            if let Err(e) = handle_connection(stream, registry_clone, persist_path_clone) {
                tracing::warn!(?e, "connection handler failed");
            }
        });
    }
}

fn handle_connection(
    mut stream: TcpStream,
    registry: Arc<Mutex<Registry>>,
    persist_path: PathBuf,
) -> Result<()> {
    let request = read_request(&mut stream)?;
    let mut listener = PersistOnChange::new(persist_path);
    let response = {
        let mut reg = registry.lock().expect("registry mutex poisoned");
        route(&request, &mut reg, &mut listener)
    };
    write_response(&mut stream, &response)?;
    Ok(())
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
        // Leak the tempdir so it lives for the duration of the test thread.
        std::mem::forget(dir);

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let registry = Arc::new(Mutex::new(Registry::with_range(PortRange {
            start: 10_000,
            end: 10_010,
        })));
        let persist_path = path.clone();
        let handle = std::thread::spawn(move || {
            // Single-shot accept loop: handle a couple of connections then exit.
            for _ in 0..3 {
                if let Ok((stream, _)) = listener.accept() {
                    let r = registry.clone();
                    let p = persist_path.clone();
                    std::thread::spawn(move || {
                        let _ = handle_connection(stream, r, p);
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
    fn end_to_end_register_then_persist() {
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
        std::thread::sleep(Duration::from_millis(100));
        let reloaded = Registry::load(&path).unwrap();
        assert_eq!(reloaded.len(), 1);
    }
}
