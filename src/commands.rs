//! High-level orchestration for the `up`, `down`, and `status` subcommands.
//!
//! The heavy lifting (config parsing, SSM port-forward, SSH reverse-tunnel,
//! process spawning, health checks, bastion control plane) lives in the
//! sibling modules and is each independently unit-tested. This module is
//! glue: it composes them in the right order, persists the resulting
//! sessions, and produces user-facing output.

use crate::aws_bastion_provisioner::AwsBastionProvisioner;
use crate::bastion_client::{self, BastionEndpoint};
use crate::bastion_protocol::{DeregisterRequest, RegisterRequest};
use crate::bastion_provisioner::{BastionProvisioner, InstanceSummary, BASTION_NAME};
use crate::config::{current_user, Config};
use crate::runner::{spawn_service, wait_for_health, HealthCheck, RunningService};
use crate::ssm::{start_port_forward, PortForwardSpec, SsmTunnel};
use crate::state::{default_state_path, Session, State};
use crate::tunnel::{open_ssh2_reverse_forward, ReverseForward, SshAuth, SshConfig};
use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

/// Default port the bastion control plane listens on. Reachable through the
/// SSM port-forward established for the SSH session, on `127.0.0.1`.
pub const DEFAULT_CONTROL_PLANE_PORT: u16 = 8443;

/// Inputs for the `status` flow; thin enough that we don't need a full
/// dependency-injection scaffolding for it.
pub struct StatusOutput {
    pub user: String,
    pub sessions: Vec<Session>,
}

pub fn status() -> Result<StatusOutput> {
    let user = current_user()?;
    let path = default_state_path()?;
    let state = State::load(&path)?;
    let sessions = state.for_user(&user).cloned().collect();
    Ok(StatusOutput { user, sessions })
}

pub fn render_status(out: &StatusOutput) -> String {
    if out.sessions.is_empty() {
        return format!("no active ephemwork sessions for {}", out.user);
    }
    let mut lines = vec![format!("active sessions for {}:", out.user)];
    for s in &out.sessions {
        lines.push(format!(
            "  {service:<20} local:{local} -> bastion:{remote}  pid={pid}  since {when}",
            service = s.service,
            local = s.local_port,
            remote = s.remote_port,
            pid = s.pid.map(|p| p.to_string()).unwrap_or_else(|| "?".into()),
            when = s.started_at.to_rfc3339(),
        ));
    }
    lines.join("\n")
}

/// What `up` returns to main.rs so the CLI layer can decide how to print.
pub struct UpOutcome {
    pub user: String,
    pub service: String,
    pub local_port: u16,
    pub remote_port: u16,
    pub header_value: String,
}

impl UpOutcome {
    pub fn header_line(&self) -> String {
        format!("X-Ephemwork: {}", self.header_value)
    }
}

/// Pure helper: produce the header value for a (user, service) pair. Trims
/// and lowercases the user identifier so the bastion can match deterministically.
pub fn header_value(user: &str, service: &str) -> String {
    format!("{}:{}", user.trim().to_lowercase(), service.trim())
}

/// Check that `service` exists in `cfg` and return its config. Pure so it's
/// easy to unit-test without touching the filesystem.
pub fn lookup_service<'a>(
    cfg: &'a Config,
    service: &str,
) -> Result<&'a crate::config::ServiceConfig> {
    cfg.service.get(service).ok_or_else(|| {
        let mut names: Vec<&String> = cfg.service.keys().collect();
        names.sort();
        let known = names
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        anyhow!("service '{service}' not found in ephemwork.toml; known: {known}")
    })
}

/// Persist a successful `up` invocation to the on-disk session state. Pure
/// over an injected path so tests don't touch `$HOME`.
pub fn record_session(state_path: &Path, session: Session) -> Result<()> {
    let mut state = State::load(state_path)?;
    state.upsert(session);
    state.save(state_path)?;
    Ok(())
}

/// Remove sessions matching the predicate from the on-disk state. Returns
/// the entries that were removed so the caller can tear down their tunnels.
pub fn forget_sessions<F>(state_path: &Path, pred: F) -> Result<Vec<Session>>
where
    F: FnMut(&Session) -> bool,
{
    let mut state = State::load(state_path)?;
    let removed = state.remove_where(pred);
    state.save(state_path)?;
    Ok(removed)
}

/// Best-effort bastion deregistration; logs but doesn't propagate the error
/// so that a flaky bastion doesn't keep stale entries in local state.
pub fn deregister_best_effort(endpoint: &BastionEndpoint, user: &str, service: &str) {
    let req = DeregisterRequest {
        user: user.into(),
        service: service.into(),
    };
    if let Err(e) = bastion_client::deregister(endpoint, &req) {
        tracing::warn!(?e, %user, %service, "bastion deregister failed; cleaning local state anyway");
    }
}

/// Register with the bastion and translate the response to the structured
/// `UpOutcome` the CLI layer prints. The actual SSM/SSH/process-spawning
/// is not in this commit; commit 7's wiring stops at exposing the public
/// control-plane registration so end-to-end tests can target it.
pub fn register_with_bastion(
    endpoint: &BastionEndpoint,
    user: &str,
    service: &str,
) -> Result<u16> {
    let resp = bastion_client::register(
        endpoint,
        &RegisterRequest {
            user: user.into(),
            service: service.into(),
        },
    )
    .context("registering with bastion control plane")?;
    Ok(resp.remote_port)
}

/// Build a Session for a freshly-registered tunnel. Separated out for testing.
pub fn session_for(
    user: &str,
    service: &str,
    local_port: u16,
    remote_port: u16,
    pid: Option<u32>,
) -> Session {
    Session {
        user: user.into(),
        service: service.into(),
        started_at: Utc::now(),
        local_port,
        remote_port,
        pid,
    }
}

/// Configuration for the `up` flow. Inputs come from the CLI args + the
/// loaded `Config`. Wrapped in a struct so the orchestration is easier to
/// test with stubbed dependencies.
#[derive(Debug, Clone)]
pub struct UpRequest {
    pub user: String,
    pub service: String,
    pub region: String,
    pub local_service_port: u16,
    pub run_command: String,
    pub health_check_path: Option<String>,
    pub ssh_username: String,
    pub ssh_keepalive: Duration,
    pub health_timeout: Duration,
}

impl UpRequest {
    /// Default SSH username for AL2023 EC2 instances.
    pub const DEFAULT_SSH_USERNAME: &'static str = "ec2-user";

    pub fn from_config(cfg: &Config, service: &str, user: &str) -> Result<Self> {
        let svc = lookup_service(cfg, service)?;
        Ok(Self {
            user: user.to_string(),
            service: service.to_string(),
            region: cfg.tunnel.region.clone(),
            local_service_port: svc.port,
            run_command: svc.run_command.clone(),
            health_check_path: svc.health_check_path.clone(),
            ssh_username: Self::DEFAULT_SSH_USERNAME.to_string(),
            ssh_keepalive: Duration::from_secs(30),
            health_timeout: Duration::from_secs(60),
        })
    }
}

/// Active resources tied to one `up` invocation. Dropped in reverse order
/// of acquisition so the laptop's state stays clean.
pub struct ActiveSession {
    pub user: String,
    pub service: String,
    pub local_port: u16,
    pub remote_port: u16,
    pub pid: u32,

    /// Order matters: drop the SSH reverse forward first (closes the
    /// bastion-side listener), then the runner (kills the local service),
    /// then the SSM tunnels (closes both `aws ssm start-session` children).
    /// `Option` lets us take ownership during cleanup.
    reverse: Option<ReverseForward>,
    runner: Option<RunningService>,
    ssh_ssm: Option<SsmTunnel>,
    cp_ssm: Option<SsmTunnel>,

    /// Endpoint of the control-plane port forward, used for deregistration.
    cp_endpoint: BastionEndpoint,
}

impl ActiveSession {
    pub fn header_value(&self) -> String {
        format!("{}:{}", self.user, self.service)
    }

    pub fn header_line(&self) -> String {
        format!("X-Ephemwork: {}", self.header_value())
    }

    /// Best-effort cleanup: deregister with the bastion, drop the SSH
    /// tunnel, the local process, and both SSM forwards. Does not propagate
    /// errors because Drop semantics already kill the children if anything
    /// fails — we just want the bastion's view to match.
    pub fn shutdown(mut self) {
        let endpoint = self.cp_endpoint.clone();
        deregister_best_effort(&endpoint, &self.user, &self.service);
        // Take + drop in dependency order.
        let _ = self.reverse.take();
        let _ = self.runner.take();
        let _ = self.ssh_ssm.take();
        let _ = self.cp_ssm.take();
    }
}

/// Launch the local service and bridge it to the bastion. The function blocks
/// nothing on its own; the caller (typically main) decides whether to keep
/// the returned `ActiveSession` alive (foreground UX) or hand it off.
pub async fn up_service(req: UpRequest) -> Result<ActiveSession> {
    let mut provisioner = AwsBastionProvisioner::new(req.region.clone()).await?;
    let bastion = locate_bastion(&mut provisioner)?;

    // Open SSM port-forward to the bastion control plane.
    let cp_ssm = start_port_forward(&PortForwardSpec {
        target: bastion.instance_id.clone(),
        remote_port: DEFAULT_CONTROL_PLANE_PORT,
        region: req.region.clone(),
    })
    .context("opening SSM port-forward to bastion control plane")?;
    let cp_endpoint = BastionEndpoint::new("127.0.0.1", cp_ssm.local_port);
    // Give the SSM session a moment to come up before we hit the endpoint.
    wait_for_local_port(cp_endpoint.port, Duration::from_secs(15))
        .context("control-plane SSM port-forward never became reachable")?;

    let remote_port = register_with_bastion(&cp_endpoint, &req.user, &req.service)?;
    tracing::info!(remote_port, "registered with bastion control plane");

    // Open SSM port-forward to the bastion's :22 for the SSH tunnel.
    let ssh_ssm = start_port_forward(&PortForwardSpec {
        target: bastion.instance_id.clone(),
        remote_port: 22,
        region: req.region.clone(),
    })
    .context("opening SSM port-forward to bastion SSH")?;
    wait_for_local_port(ssh_ssm.local_port, Duration::from_secs(15))
        .context("SSH SSM port-forward never became reachable")?;

    // Spawn the local service and wait for its health endpoint, if any.
    let service = spawn_service(&req.run_command, Stdio::inherit(), Stdio::inherit())?;
    let pid = service.pid;
    if let Some(path) = &req.health_check_path {
        wait_for_health(&HealthCheck {
            host: "127.0.0.1",
            port: req.local_service_port,
            path,
            overall_timeout: req.health_timeout,
            poll_interval: Duration::from_millis(250),
        })
        .with_context(|| {
            format!(
                "service {:?} never returned 2xx on {path} within {:?}",
                req.service, req.health_timeout
            )
        })?;
    }

    let reverse = open_ssh2_reverse_forward(
        &SshConfig {
            host: "127.0.0.1".into(),
            port: ssh_ssm.local_port,
            username: req.ssh_username.clone(),
            auth: SshAuth::Agent,
            keepalive: req.ssh_keepalive,
        },
        req.local_service_port,
        remote_port,
    )?;

    // Persist for `status` / orphan cleanup.
    let session = session_for(
        &req.user,
        &req.service,
        req.local_service_port,
        remote_port,
        Some(pid),
    );
    record_session(&default_state_path()?, session)?;

    Ok(ActiveSession {
        user: req.user,
        service: req.service,
        local_port: req.local_service_port,
        remote_port,
        pid,
        reverse: Some(reverse),
        runner: Some(service),
        ssh_ssm: Some(ssh_ssm),
        cp_ssm: Some(cp_ssm),
        cp_endpoint,
    })
}

fn locate_bastion(provisioner: &mut dyn BastionProvisioner) -> Result<InstanceSummary> {
    provisioner
        .find_instance_by_name(BASTION_NAME)?
        .ok_or_else(|| {
            anyhow!(
                "no bastion found (no instance tagged Name={BASTION_NAME}). Run \
                 `ephemwork bastion init --live ...` to provision one."
            )
        })
}

/// Poll a localhost TCP port until it accepts a connection, with a deadline.
/// Used after `aws ssm start-session` to avoid sending a request to a
/// not-yet-listening proxy.
fn wait_for_local_port(port: u16, timeout: Duration) -> Result<()> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if std::net::TcpStream::connect_timeout(
            &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
            Duration::from_millis(500),
        )
        .is_ok()
        {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(anyhow!(
                "port 127.0.0.1:{port} did not become reachable within {timeout:?}"
            ));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Tear down sessions for the current user. If `service` is `Some`, only that
/// session; otherwise all sessions. Deregisters with the bastion (best
/// effort) and removes them from local state.
pub async fn down_service(service: Option<String>) -> Result<Vec<Session>> {
    let user = current_user()?;
    let cfg = Config::load()?;
    let state_path = default_state_path()?;
    let state = State::load(&state_path)?;
    let candidates: Vec<Session> = state
        .for_user(&user)
        .filter(|s| service.as_deref().map_or(true, |svc| s.service == svc))
        .cloned()
        .collect();

    if candidates.is_empty() {
        return Ok(Vec::new());
    }

    // Best-effort bastion deregistration through a fresh SSM tunnel. If the
    // bastion is unreachable we still clear local state because the laptop
    // can't drive what it can't reach.
    if let Err(e) = deregister_via_bastion(&cfg, &user, &candidates).await {
        tracing::warn!(?e, "bastion deregistration failed; clearing local state anyway");
    }

    let removed = forget_sessions(&state_path, |s| {
        s.user == user && service.as_deref().map_or(true, |svc| s.service == svc)
    })?;
    Ok(removed)
}

async fn deregister_via_bastion(cfg: &Config, user: &str, sessions: &[Session]) -> Result<()> {
    let mut provisioner = AwsBastionProvisioner::new(cfg.tunnel.region.clone()).await?;
    let bastion = match provisioner.find_instance_by_name(BASTION_NAME)? {
        Some(b) => b,
        None => return Ok(()),
    };
    let cp_ssm = start_port_forward(&PortForwardSpec {
        target: bastion.instance_id,
        remote_port: DEFAULT_CONTROL_PLANE_PORT,
        region: cfg.tunnel.region.clone(),
    })?;
    wait_for_local_port(cp_ssm.local_port, Duration::from_secs(10))?;
    let endpoint = BastionEndpoint::new("127.0.0.1", cp_ssm.local_port);
    for s in sessions {
        deregister_best_effort(&endpoint, user, &s.service);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ServiceConfig, TunnelConfig};
    use std::collections::HashMap;
    use tempfile::tempdir;

    fn cfg_with(services: &[(&str, u16)]) -> Config {
        let mut service = HashMap::new();
        for (name, port) in services {
            service.insert(
                (*name).into(),
                ServiceConfig {
                    port: *port,
                    build_command: None,
                    run_command: "x".into(),
                    health_check_path: None,
                },
            );
        }
        Config {
            tunnel: TunnelConfig {
                r#type: "ec2".into(),
                region: "us-east-1".into(),
                instance_type: "t4g.nano".into(),
            },
            service,
        }
    }

    #[test]
    fn header_value_lowercases_user_and_keeps_service_case() {
        assert_eq!(header_value("Matheus", "API-v2"), "matheus:API-v2");
    }

    #[test]
    fn header_value_trims_whitespace() {
        assert_eq!(header_value("  alice ", "  api "), "alice:api");
    }

    #[test]
    fn lookup_service_returns_match() {
        let cfg = cfg_with(&[("api", 8000), ("worker", 9000)]);
        let svc = lookup_service(&cfg, "api").unwrap();
        assert_eq!(svc.port, 8000);
    }

    #[test]
    fn lookup_service_lists_known_names_on_miss() {
        let cfg = cfg_with(&[("api", 8000), ("worker", 9000)]);
        let err = lookup_service(&cfg, "frontend").unwrap_err().to_string();
        assert!(err.contains("frontend"), "got: {err}");
        assert!(err.contains("api"), "got: {err}");
        assert!(err.contains("worker"), "got: {err}");
    }

    #[test]
    fn record_then_forget_round_trips() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("state.json");
        let s = session_for("matheus", "api", 8000, 9001, Some(42));
        record_session(&path, s.clone()).unwrap();

        let state = State::load(&path).unwrap();
        assert_eq!(state.sessions.len(), 1);

        let removed =
            forget_sessions(&path, |sess| sess.user == "matheus" && sess.service == "api")
                .unwrap();
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].remote_port, 9001);

        let state = State::load(&path).unwrap();
        assert!(state.sessions.is_empty());
    }

    #[test]
    fn forget_sessions_filters_by_user() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("state.json");
        record_session(&path, session_for("alice", "api", 1, 2, None)).unwrap();
        record_session(&path, session_for("bob", "api", 3, 4, None)).unwrap();
        let removed = forget_sessions(&path, |s| s.user == "alice").unwrap();
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].user, "alice");
        let state = State::load(&path).unwrap();
        assert_eq!(state.sessions.len(), 1);
        assert_eq!(state.sessions[0].user, "bob");
    }

    #[test]
    fn render_status_empty_message() {
        let out = StatusOutput {
            user: "matheus".into(),
            sessions: vec![],
        };
        let s = render_status(&out);
        assert!(s.contains("matheus"));
        assert!(s.to_lowercase().contains("no active"));
    }

    #[test]
    fn render_status_lists_sessions() {
        let out = StatusOutput {
            user: "matheus".into(),
            sessions: vec![session_for("matheus", "api", 8000, 9001, Some(42))],
        };
        let s = render_status(&out);
        assert!(s.contains("api"));
        assert!(s.contains("8000"));
        assert!(s.contains("9001"));
        assert!(s.contains("42"));
    }

    #[test]
    fn up_outcome_header_line_format() {
        let out = UpOutcome {
            user: "matheus".into(),
            service: "api".into(),
            local_port: 8000,
            remote_port: 9001,
            header_value: header_value("matheus", "api"),
        };
        assert_eq!(out.header_line(), "X-Ephemwork: matheus:api");
    }

    #[test]
    fn up_request_pulls_fields_from_config_and_user() {
        let cfg = cfg_with(&[("api", 8000)]);
        let req = UpRequest::from_config(&cfg, "api", "matheus").unwrap();
        assert_eq!(req.user, "matheus");
        assert_eq!(req.service, "api");
        assert_eq!(req.region, "us-east-1");
        assert_eq!(req.local_service_port, 8000);
        assert_eq!(req.run_command, "x");
        assert_eq!(req.health_check_path, None);
        assert_eq!(req.ssh_username, UpRequest::DEFAULT_SSH_USERNAME);
        assert!(req.ssh_keepalive >= Duration::from_secs(1));
        assert!(req.health_timeout >= Duration::from_secs(1));
    }

    #[test]
    fn up_request_errors_on_unknown_service() {
        let cfg = cfg_with(&[("api", 8000)]);
        let err = UpRequest::from_config(&cfg, "ghost", "matheus")
            .unwrap_err()
            .to_string();
        assert!(err.contains("ghost"), "got: {err}");
    }

    #[test]
    fn wait_for_local_port_returns_when_listener_present() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        // Spawn a thread that just accepts connections so the OS keeps the
        // port reachable for the test.
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                drop(stream);
            }
        });
        wait_for_local_port(port, Duration::from_secs(2)).unwrap();
    }

    #[test]
    fn wait_for_local_port_times_out_when_nothing_listens() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let err = wait_for_local_port(port, Duration::from_millis(300))
            .unwrap_err()
            .to_string();
        assert!(err.contains("did not become reachable"), "got: {err}");
    }

    #[test]
    fn active_session_header_format() {
        let sess = ActiveSession {
            user: "matheus".into(),
            service: "api".into(),
            local_port: 8000,
            remote_port: 9001,
            pid: 42,
            reverse: None,
            runner: None,
            ssh_ssm: None,
            cp_ssm: None,
            cp_endpoint: BastionEndpoint::new("127.0.0.1", 5555),
        };
        assert_eq!(sess.header_value(), "matheus:api");
        assert_eq!(sess.header_line(), "X-Ephemwork: matheus:api");
    }
}
