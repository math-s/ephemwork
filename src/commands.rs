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
use crate::bastion_provisioner::{BastionContext, BastionProvisioner, InstanceSummary};
use crate::config::{current_user, Config};
use crate::runner::{
    assert_port_free, run_bootstrap, spawn_service, wait_for_health, HealthCheck,
    RunningService,
};
use crate::ssm::{
    assert_plugin_available, parse_forward_port_spec, start_port_forward,
    start_remote_host_forward, ForwardPortSpec, PortForwardSpec, RemoteHostForwardSpec, SsmTunnel,
};
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
///
/// `forward_local_ports` should contain only the ports this session
/// actually opened (not ones it borrowed from a sibling). Sibling
/// sessions consult this list to decide whether they need to open
/// their own SSM tunnel for a given `forward_ports` entry.
pub fn session_for(
    user: &str,
    service: &str,
    local_port: u16,
    remote_port: u16,
    pid: Option<u32>,
    forward_local_ports: Vec<u16>,
) -> Session {
    Session {
        user: user.into(),
        service: service.into(),
        started_at: Utc::now(),
        local_port,
        remote_port,
        pid,
        forward_local_ports,
    }
}

/// Probe whether `pid` exists and we have permission to signal it.
/// Used to decide whether a `forward_owner` claim in state.json is
/// still live or stale. `kill(pid, 0)` is signal-free; it just
/// returns 0 on success and -1 with errno=ESRCH for a dead pid.
fn pid_is_alive(pid: u32) -> bool {
    // SAFETY: libc::kill is FFI; sig=0 has no side effects.
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

/// Decide whether a `forward_ports` entry can ride on an existing
/// SSM tunnel opened by a sibling session of the same user. Returns:
///   - `Ok(true)`  → port is already forwarded by a live sibling;
///                    don't open a new tunnel.
///   - `Ok(false)` → no live owner; the caller should open the tunnel.
///   - `Err(...)`  → ambiguous (port bound by an unknown process, or
///                    bound by a *dead* sibling whose tunnel we can't
///                    reuse safely).
fn check_forward_reuse(
    state: &State,
    user: &str,
    spec: &ForwardPortSpec,
) -> Result<bool> {
    let Some(owner) = state.forward_owner(user, spec.local_port) else {
        return Ok(false);
    };
    let pid = owner.pid.unwrap_or(0);
    if pid == 0 || !pid_is_alive(pid) {
        return Err(anyhow!(
            "local port {} is recorded as owned by sibling session \
             {:?} (pid {:?}), but that process is no longer running. \
             Run `ephemwork down {service}` to clear the stale entry, \
             then retry.",
            spec.local_port,
            owner.service,
            owner.pid,
            service = owner.service
        ));
    }
    tracing::info!(
        local = spec.local_port,
        host = %spec.remote_host,
        remote = spec.remote_port,
        owner_service = %owner.service,
        owner_pid = ?owner.pid,
        "reusing forward already opened by sibling session"
    );
    Ok(true)
}

/// Configuration for the `up` flow. Inputs come from the CLI args + the
/// loaded `Config`. Wrapped in a struct so the orchestration is easier to
/// test with stubbed dependencies.
#[derive(Debug, Clone)]
pub struct UpRequest {
    pub user: String,
    pub service: String,
    pub region: String,
    /// Port the local service listens on. `None` means worker mode:
    /// no inbound HTTP routing, no bastion registration, no SSH reverse
    /// tunnel. ephemwork just runs `bootstrap_command` then
    /// `run_command` and watches the child process.
    pub local_service_port: Option<u16>,
    pub run_command: String,
    pub health_check_path: Option<String>,
    pub ssh_username: String,
    pub ssh_keepalive: Duration,
    pub health_timeout: Duration,
    /// Raw `"local:host:remote"` strings from `service.<name>.forward_ports`.
    /// Validated at request build time; opened via SSM in `up_service`.
    pub forward_ports: Vec<String>,
    /// Optional shell command run before `run_command` (and before any
    /// tunnel is opened). See `ServiceConfig::bootstrap_command`.
    pub bootstrap_command: Option<String>,
}

impl UpRequest {
    /// Default SSH username for AL2023 EC2 instances.
    pub const DEFAULT_SSH_USERNAME: &'static str = "ec2-user";

    pub fn from_config(cfg: &Config, service: &str, user: &str) -> Result<Self> {
        let svc = lookup_service(cfg, service)?;
        // Validate every forward spec early so a typo in ephemwork.toml
        // surfaces before we open any SSM tunnel.
        for raw in &svc.forward_ports {
            parse_forward_port_spec(raw)?;
        }
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
            forward_ports: svc.forward_ports.clone(),
            bootstrap_command: svc.bootstrap_command.clone(),
        })
    }
}

/// Active resources tied to one `up` invocation. Dropped in reverse order
/// of acquisition so the laptop's state stays clean.
pub struct ActiveSession {
    pub user: String,
    pub service: String,
    /// `None` for worker services (no inbound routing).
    pub local_port: Option<u16>,
    /// `None` for worker services (no bastion registration).
    pub remote_port: Option<u16>,
    pub pid: u32,

    /// Order matters: drop the SSH reverse forward first (closes the
    /// bastion-side listener), then the runner (kills the local service),
    /// then the SSM tunnels (closes both `aws ssm start-session` children),
    /// then any outbound forward-port SSM tunnels.
    /// `Option` lets us take ownership during cleanup.
    reverse: Option<ReverseForward>,
    runner: Option<RunningService>,
    ssh_ssm: Option<SsmTunnel>,
    cp_ssm: Option<SsmTunnel>,
    forward_ssm: Vec<SsmTunnel>,

    /// Endpoint of the control-plane port forward, used for deregistration.
    /// `None` for worker services (no control plane was opened).
    cp_endpoint: Option<BastionEndpoint>,
}

impl ActiveSession {
    pub fn header_value(&self) -> String {
        format!("{}:{}", self.user, self.service)
    }

    pub fn header_line(&self) -> String {
        format!("X-Ephemwork: {}", self.header_value())
    }

    /// True when the reverse-SSH worker reported a fatal SSH error and
    /// gave up. Used by `main.rs::up` to race ctrl_c with tunnel death so
    /// the bastion's stale registry entry doesn't keep 502'ing forever.
    pub fn tunnel_is_dead(&self) -> bool {
        self.reverse.as_ref().map(|r| r.is_dead()).unwrap_or(false)
    }

    /// Best-effort cleanup: deregister with the bastion, drop the SSH
    /// tunnel, the local process, and both SSM forwards. Does not propagate
    /// errors because Drop semantics already kill the children if anything
    /// fails — we just want the bastion's view to match.
    pub fn shutdown(mut self) {
        if let Some(endpoint) = self.cp_endpoint.clone() {
            deregister_best_effort(&endpoint, &self.user, &self.service);
        }
        // Take + drop in dependency order.
        let _ = self.reverse.take();
        let _ = self.runner.take();
        let _ = self.ssh_ssm.take();
        let _ = self.cp_ssm.take();
        self.forward_ssm.clear();
    }
}

/// Launch the local service and bridge it to the bastion. The function blocks
/// nothing on its own; the caller (typically main) decides whether to keep
/// the returned `ActiveSession` alive (foreground UX) or hand it off.
pub async fn up_service(req: UpRequest, ctx: BastionContext) -> Result<ActiveSession> {
    // Worker services (no inbound port) skip the inbound-routing path:
    // no SSH reverse forward, no ALB rule, no bastion control-plane
    // registration. They may still open outbound SSM forwards through
    // the bastion (e.g. so the worker can query staging RDS).
    let Some(local_service_port) = req.local_service_port else {
        return up_worker(req, ctx).await;
    };

    // Fail fast if the SSM plugin isn't installed: every port-forward
    // would otherwise just time out at 15s with no hint.
    assert_plugin_available().context("session-manager-plugin pre-flight")?;

    // Fail fast if a previous run left a listener on the local service
    // port; otherwise spawn_service ends up racing it and uvicorn (or
    // similar) errors deep into startup with a cryptic EADDRINUSE.
    assert_port_free(local_service_port)
        .with_context(|| format!("local port for service {:?}", req.service))?;

    // Project-supplied bootstrap (e.g. hydrate .env.staging from Secrets
    // Manager). Runs before any tunnel is opened so a credential-fetch
    // failure aborts before we touch AWS.
    if let Some(cmd) = req.bootstrap_command.as_deref() {
        tracing::info!(bootstrap = %cmd, "running bootstrap_command");
        run_bootstrap(cmd).context("bootstrap_command")?;
    }

    let mut provisioner =
        AwsBastionProvisioner::new(req.region.clone(), ctx.clone()).await?;
    let bastion = locate_bastion(&mut provisioner, &ctx)?;

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

    // Outbound forwards through the bastion to VPC-private hosts (e.g.
    // staging RDS). Opened before the local service starts so e.g. uvicorn
    // can resolve its DB connection on first boot. If a sibling session
    // (same user) has already opened this local port, reuse instead of
    // colliding — keeps `up api` + `up engine-worker` from fighting over
    // 5432 when both declare the same forward.
    let state_for_reuse = State::load(&default_state_path()?)?;
    let mut forward_ssm: Vec<SsmTunnel> = Vec::new();
    let mut owned_local_ports: Vec<u16> = Vec::new();
    for raw in &req.forward_ports {
        let spec = parse_forward_port_spec(raw)?;
        if check_forward_reuse(&state_for_reuse, &req.user, &spec)? {
            // Sibling owns it — nothing to open, nothing to close on Drop.
            continue;
        }
        let tunnel = start_remote_host_forward(&RemoteHostForwardSpec {
            target: bastion.instance_id.clone(),
            remote_host: spec.remote_host.clone(),
            remote_port: spec.remote_port,
            local_port: spec.local_port,
            region: req.region.clone(),
        })
        .with_context(|| format!("opening forward {raw}"))?;
        wait_for_local_port(spec.local_port, Duration::from_secs(15))
            .with_context(|| format!("forward {raw} never became reachable"))?;
        tracing::info!(
            local = spec.local_port,
            host = %spec.remote_host,
            remote = spec.remote_port,
            "outbound forward open"
        );
        forward_ssm.push(tunnel);
        owned_local_ports.push(spec.local_port);
    }

    // Spawn the local service and wait for its health endpoint, if any.
    let service = spawn_service(&req.run_command, Stdio::inherit(), Stdio::inherit())?;
    let pid = service.pid;
    if let Some(path) = &req.health_check_path {
        wait_for_health(&HealthCheck {
            host: "127.0.0.1",
            port: local_service_port,
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
        local_service_port,
        remote_port,
    )?;

    // Persist for `status` / orphan cleanup. `forward_local_ports`
    // records only the ones this session opened (not borrowed); a
    // future sibling consults this list before opening its own.
    let session = session_for(
        &req.user,
        &req.service,
        local_service_port,
        remote_port,
        Some(pid),
        owned_local_ports,
    );
    record_session(&default_state_path()?, session)?;

    Ok(ActiveSession {
        user: req.user,
        service: req.service,
        local_port: Some(local_service_port),
        remote_port: Some(remote_port),
        pid,
        reverse: Some(reverse),
        runner: Some(service),
        ssh_ssm: Some(ssh_ssm),
        cp_ssm: Some(cp_ssm),
        forward_ssm,
        cp_endpoint: Some(cp_endpoint),
    })
}

/// Worker-mode `up`: bootstrap_command + outbound forward_ports +
/// run_command. No inbound HTTP routing (no SSH reverse forward, no
/// ALB rule, no bastion registration), but the worker may still need
/// to talk to VPC-private hosts (e.g. staging RDS) — those use the
/// same SSM `AWS-StartPortForwardingSessionToRemoteHost` machinery
/// the HTTP path uses, so the bastion still gets provisioned/located
/// when forward_ports is non-empty. With no forward_ports, this is
/// a pure local spawn.
async fn up_worker(req: UpRequest, ctx: BastionContext) -> Result<ActiveSession> {
    let needs_bastion = !req.forward_ports.is_empty();

    if needs_bastion {
        assert_plugin_available().context("session-manager-plugin pre-flight")?;
    }

    if let Some(cmd) = req.bootstrap_command.as_deref() {
        tracing::info!(bootstrap = %cmd, "running bootstrap_command");
        run_bootstrap(cmd).context("bootstrap_command")?;
    }

    let mut forward_ssm: Vec<SsmTunnel> = Vec::new();
    let mut owned_local_ports: Vec<u16> = Vec::new();
    if needs_bastion {
        let mut provisioner =
            AwsBastionProvisioner::new(req.region.clone(), ctx.clone()).await?;
        let bastion = locate_bastion(&mut provisioner, &ctx)?;

        let state_for_reuse = State::load(&default_state_path()?)?;
        for raw in &req.forward_ports {
            let spec = parse_forward_port_spec(raw)?;
            if check_forward_reuse(&state_for_reuse, &req.user, &spec)? {
                continue;
            }
            assert_port_free(spec.local_port).with_context(|| {
                format!(
                    "forward {raw}: local port in use by an unknown \
                     process (no sibling ephemwork session owns it)"
                )
            })?;
            let tunnel = start_remote_host_forward(&RemoteHostForwardSpec {
                target: bastion.instance_id.clone(),
                remote_host: spec.remote_host.clone(),
                remote_port: spec.remote_port,
                local_port: spec.local_port,
                region: req.region.clone(),
            })
            .with_context(|| format!("opening forward {raw}"))?;
            wait_for_local_port(spec.local_port, Duration::from_secs(15))
                .with_context(|| format!("forward {raw} never became reachable"))?;
            tracing::info!(
                local = spec.local_port,
                host = %spec.remote_host,
                remote = spec.remote_port,
                "outbound forward open"
            );
            forward_ssm.push(tunnel);
            owned_local_ports.push(spec.local_port);
        }
    }

    let service = spawn_service(&req.run_command, Stdio::inherit(), Stdio::inherit())?;
    let pid = service.pid;

    // local_port=0/remote_port=0 in state.json marks this as a worker.
    let session = session_for(&req.user, &req.service, 0, 0, Some(pid), owned_local_ports);
    record_session(&default_state_path()?, session)?;

    Ok(ActiveSession {
        user: req.user,
        service: req.service,
        local_port: None,
        remote_port: None,
        pid,
        reverse: None,
        runner: Some(service),
        ssh_ssm: None,
        cp_ssm: None,
        forward_ssm,
        cp_endpoint: None,
    })
}

fn locate_bastion(
    provisioner: &mut dyn BastionProvisioner,
    ctx: &BastionContext,
) -> Result<InstanceSummary> {
    let name = ctx.instance_name();
    provisioner
        .find_instance_by_name(&name)?
        .ok_or_else(|| {
            anyhow!(
                "no bastion found (no instance tagged Name={name}). Run \
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
    let ctx = BastionContext::new(cfg.tunnel.project_name.clone());
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

    if let Err(e) = deregister_via_bastion(&cfg, &ctx, &user, &candidates).await {
        tracing::warn!(?e, "bastion deregistration failed; clearing local state anyway");
    }

    let removed = forget_sessions(&state_path, |s| {
        s.user == user && service.as_deref().map_or(true, |svc| s.service == svc)
    })?;
    Ok(removed)
}

async fn deregister_via_bastion(
    cfg: &Config,
    ctx: &BastionContext,
    user: &str,
    sessions: &[Session],
) -> Result<()> {
    assert_plugin_available().context("session-manager-plugin pre-flight")?;
    let mut provisioner =
        AwsBastionProvisioner::new(cfg.tunnel.region.clone(), ctx.clone()).await?;
    let bastion = match provisioner.find_instance_by_name(&ctx.instance_name())? {
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
                    port: Some(*port),
                    build_command: None,
                    run_command: "x".into(),
                    health_check_path: None,
                    forward_ports: Vec::new(),
                    bootstrap_command: None,
                },
            );
        }
        Config {
            tunnel: TunnelConfig {
                r#type: "ec2".into(),
                region: "us-east-1".into(),
                instance_type: "t4g.nano".into(),
                project_name: "demo".into(),
                expected_vpc_id: None,
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
        assert_eq!(svc.port, Some(8000));
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
        let s = session_for("matheus", "api", 8000, 9001, Some(42), Vec::new());
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
        record_session(&path, session_for("alice", "api", 1, 2, None, Vec::new())).unwrap();
        record_session(&path, session_for("bob", "api", 3, 4, None, Vec::new())).unwrap();
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
            sessions: vec![session_for("matheus", "api", 8000, 9001, Some(42), Vec::new())],
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
        assert_eq!(req.local_service_port, Some(8000));
        assert_eq!(req.run_command, "x");
        assert_eq!(req.health_check_path, None);
        assert_eq!(req.ssh_username, UpRequest::DEFAULT_SSH_USERNAME);
        assert!(req.ssh_keepalive >= Duration::from_secs(1));
        assert!(req.health_timeout >= Duration::from_secs(1));
        assert!(req.forward_ports.is_empty());
    }

    #[test]
    fn up_request_propagates_forward_ports() {
        let mut cfg = cfg_with(&[("api", 8000)]);
        cfg.service.get_mut("api").unwrap().forward_ports =
            vec!["5432:rds.example.com:5432".into()];
        let req = UpRequest::from_config(&cfg, "api", "matheus").unwrap();
        assert_eq!(req.forward_ports, vec!["5432:rds.example.com:5432"]);
    }

    #[test]
    fn up_request_propagates_bootstrap_command() {
        let mut cfg = cfg_with(&[("api", 8000)]);
        cfg.service.get_mut("api").unwrap().bootstrap_command =
            Some("./scripts/bootstrap.sh".into());
        let req = UpRequest::from_config(&cfg, "api", "matheus").unwrap();
        assert_eq!(req.bootstrap_command.as_deref(), Some("./scripts/bootstrap.sh"));
    }

    #[test]
    fn up_request_no_bootstrap_command_by_default() {
        let cfg = cfg_with(&[("api", 8000)]);
        let req = UpRequest::from_config(&cfg, "api", "matheus").unwrap();
        assert!(req.bootstrap_command.is_none());
    }

    #[test]
    fn up_request_propagates_some_port_for_http_service() {
        let cfg = cfg_with(&[("api", 8000)]);
        let req = UpRequest::from_config(&cfg, "api", "matheus").unwrap();
        assert_eq!(req.local_service_port, Some(8000));
    }

    #[test]
    fn up_request_propagates_none_port_for_worker_service() {
        let mut cfg = cfg_with(&[("engine", 1234)]);
        // Simulate a worker service: omit the port. cfg_with requires a
        // u16, so reach in and clear it after construction.
        cfg.service.get_mut("engine").unwrap().port = None;
        let req = UpRequest::from_config(&cfg, "engine", "matheus").unwrap();
        assert!(req.local_service_port.is_none());
    }

    #[test]
    fn up_request_rejects_malformed_forward_port_at_build_time() {
        let mut cfg = cfg_with(&[("api", 8000)]);
        cfg.service.get_mut("api").unwrap().forward_ports = vec!["not-a-spec".into()];
        let err = UpRequest::from_config(&cfg, "api", "matheus")
            .unwrap_err()
            .to_string();
        assert!(err.contains("not-a-spec"), "got: {err}");
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
            local_port: Some(8000),
            remote_port: Some(9001),
            pid: 42,
            reverse: None,
            runner: None,
            ssh_ssm: None,
            cp_ssm: None,
            forward_ssm: Vec::new(),
            cp_endpoint: Some(BastionEndpoint::new("127.0.0.1", 5555)),
        };
        assert_eq!(sess.header_value(), "matheus:api");
        assert_eq!(sess.header_line(), "X-Ephemwork: matheus:api");
    }

    #[tokio::test]
    async fn up_worker_runs_command_without_bastion() {
        // Spawn a worker that prints to stdout and exits; ephemwork
        // doesn't supervise the process state in this unit test, but
        // the side effect (the file written by `sh -c`) proves the
        // run_command actually fired and the bootstrap_command ran
        // first. No bastion, no SSM, no SSH — purely local.
        let dir = tempdir().unwrap();
        let bootstrap_marker = dir.path().join("bootstrap.txt");
        let run_marker = dir.path().join("run.txt");

        let req = UpRequest {
            user: "matheus".into(),
            service: "engine-worker".into(),
            region: "us-east-1".into(),
            local_service_port: None,
            run_command: format!("touch {} && sleep 0.05", run_marker.display()),
            health_check_path: None,
            ssh_username: UpRequest::DEFAULT_SSH_USERNAME.into(),
            ssh_keepalive: Duration::from_secs(30),
            health_timeout: Duration::from_secs(5),
            forward_ports: Vec::new(),
            bootstrap_command: Some(format!("touch {}", bootstrap_marker.display())),
        };
        let ctx = BastionContext::new("demo");
        let session = up_worker(req, ctx).await.unwrap();

        // bootstrap_command runs synchronously before run_command; its
        // marker must exist by the time up_worker returns.
        assert!(bootstrap_marker.exists(), "bootstrap marker missing");
        assert!(session.local_port.is_none());
        assert!(session.remote_port.is_none());
        assert!(session.cp_endpoint.is_none());
        assert!(session.reverse.is_none());

        // Give the spawned `touch` a moment to land before we tear down.
        std::thread::sleep(Duration::from_millis(150));
        assert!(run_marker.exists(), "run marker missing");

        // Worker shutdown must not call deregister (cp_endpoint is None).
        // If it did, this would try to talk to localhost:0 and panic.
        session.shutdown();
    }

    #[tokio::test]
    async fn up_worker_aborts_on_failed_bootstrap() {
        let req = UpRequest {
            user: "matheus".into(),
            service: "engine-worker".into(),
            region: "us-east-1".into(),
            local_service_port: None,
            run_command: "true".into(),
            health_check_path: None,
            ssh_username: UpRequest::DEFAULT_SSH_USERNAME.into(),
            ssh_keepalive: Duration::from_secs(30),
            health_timeout: Duration::from_secs(5),
            forward_ports: Vec::new(),
            bootstrap_command: Some("exit 7".into()),
        };
        let ctx = BastionContext::new("demo");
        let err = match up_worker(req, ctx).await {
            Ok(_) => panic!("expected bootstrap_command failure"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("bootstrap_command"), "got: {err}");
    }

    fn forward_spec(local: u16) -> ForwardPortSpec {
        ForwardPortSpec {
            local_port: local,
            remote_host: "rds.example.com".into(),
            remote_port: 5432,
        }
    }

    #[test]
    fn check_forward_reuse_returns_false_when_no_owner() {
        let state = State::default();
        let reused = check_forward_reuse(&state, "alice", &forward_spec(5432)).unwrap();
        assert!(!reused);
    }

    #[test]
    fn check_forward_reuse_returns_true_when_live_sibling_owns_it() {
        // Use our own pid as the "live" sibling — it's guaranteed to
        // exist for the duration of this test.
        let our_pid = std::process::id();
        let mut state = State::default();
        state.upsert(session_for(
            "alice",
            "api",
            8000,
            10000,
            Some(our_pid),
            vec![5432],
        ));
        let reused = check_forward_reuse(&state, "alice", &forward_spec(5432)).unwrap();
        assert!(reused);
    }

    #[test]
    fn check_forward_reuse_errors_on_stale_dead_owner() {
        // Pick a pid that's almost certainly dead (max u32).
        let mut state = State::default();
        state.upsert(session_for(
            "alice",
            "api",
            8000,
            10000,
            Some(u32::MAX - 1),
            vec![5432],
        ));
        let err = check_forward_reuse(&state, "alice", &forward_spec(5432))
            .unwrap_err()
            .to_string();
        assert!(err.contains("no longer running"), "got: {err}");
        assert!(err.contains("ephemwork down"), "got: {err}");
    }

    #[test]
    fn check_forward_reuse_ignores_other_users() {
        let our_pid = std::process::id();
        let mut state = State::default();
        // Bob owns 5432 — alice's lookup must NOT reuse it.
        state.upsert(session_for(
            "bob",
            "api",
            8000,
            10000,
            Some(our_pid),
            vec![5432],
        ));
        let reused = check_forward_reuse(&state, "alice", &forward_spec(5432)).unwrap();
        assert!(!reused);
    }
}
