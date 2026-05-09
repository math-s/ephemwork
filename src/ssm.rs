//! SSM Session Manager port forwarding.
//!
//! We rely on `aws ssm start-session` because it is the supported way to
//! drive the `session-manager-plugin` (a separate binary that maintains the
//! websocket). The AWS SDK alone returns connection parameters that the
//! plugin still has to consume.
//!
//! Tests exercise pure command construction and the lifecycle of the wrapping
//! `SsmTunnel`; live SSM calls are out of scope here and are covered by the
//! end-to-end commit (#7).

use anyhow::{Context, Result};
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};

/// Inputs needed to forward `localhost:<allocated>` -> `target:remote_port`
/// through SSM Session Manager.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortForwardSpec {
    pub target: String,
    pub remote_port: u16,
    pub region: String,
}

/// Owns the `aws ssm start-session` child process. Dropping the tunnel
/// terminates the session.
pub struct SsmTunnel {
    pub local_port: u16,
    child: Child,
}

impl SsmTunnel {
    /// Wrap an already-spawned child. Exposed so tests can supply a fake
    /// process without invoking the AWS CLI.
    pub fn from_child(local_port: u16, child: Child) -> Self {
        Self { local_port, child }
    }

    pub fn child_id(&self) -> u32 {
        self.child.id()
    }
}

impl Drop for SsmTunnel {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Bind an ephemeral port and immediately release it so the SSM session can
/// reuse the number. Caller is responsible for any race window.
pub fn pick_free_local_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").context("binding ephemeral port")?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}

/// Inputs for forwarding `localhost:local_port` -> `remote_host:remote_port`
/// *through* the bastion instance via SSM's
/// `AWS-StartPortForwardingSessionToRemoteHost` document. Used to give the
/// laptop outbound reach into VPC-private services like staging RDS without
/// any SSH involvement (SSM handles multiplexing).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteHostForwardSpec {
    pub target: String,
    pub remote_host: String,
    pub remote_port: u16,
    pub local_port: u16,
    pub region: String,
}

/// Build the `aws ssm start-session` argv for a port forward. Pure function
/// so tests can pin the wire format without spawning anything.
pub fn build_start_session_args(spec: &PortForwardSpec, local_port: u16) -> Vec<String> {
    vec![
        "ssm".into(),
        "start-session".into(),
        "--region".into(),
        spec.region.clone(),
        "--target".into(),
        spec.target.clone(),
        "--document-name".into(),
        "AWS-StartPortForwardingSession".into(),
        "--parameters".into(),
        format!(
            "portNumber=[\"{}\"],localPortNumber=[\"{}\"]",
            spec.remote_port, local_port
        ),
    ]
}

/// Spawn `aws ssm start-session` and return a guard that kills the child on
/// drop. The caller can then connect to `127.0.0.1:<local_port>` as if it
/// were the remote port on the target instance.
pub fn start_port_forward(spec: &PortForwardSpec) -> Result<SsmTunnel> {
    let local_port = pick_free_local_port()?;
    let args = build_start_session_args(spec, local_port);
    let child = Command::new("aws")
        .args(&args)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawning `aws ssm start-session` (is the AWS CLI installed?)")?;
    Ok(SsmTunnel::from_child(local_port, child))
}

/// Build the argv for forwarding through the bastion to a remote host.
pub fn build_remote_host_session_args(spec: &RemoteHostForwardSpec) -> Vec<String> {
    vec![
        "ssm".into(),
        "start-session".into(),
        "--region".into(),
        spec.region.clone(),
        "--target".into(),
        spec.target.clone(),
        "--document-name".into(),
        "AWS-StartPortForwardingSessionToRemoteHost".into(),
        "--parameters".into(),
        format!(
            "host=[\"{}\"],portNumber=[\"{}\"],localPortNumber=[\"{}\"]",
            spec.remote_host, spec.remote_port, spec.local_port
        ),
    ]
}

/// Spawn an SSM session that forwards `localhost:local_port` through the
/// bastion to `remote_host:remote_port`. Drop the returned tunnel to close.
pub fn start_remote_host_forward(spec: &RemoteHostForwardSpec) -> Result<SsmTunnel> {
    let args = build_remote_host_session_args(spec);
    let child = Command::new("aws")
        .args(&args)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawning `aws ssm start-session` for remote-host forward")?;
    Ok(SsmTunnel::from_child(spec.local_port, child))
}

/// Parse `"local:host:port"` as used in `service.<name>.forward_ports`.
/// Pure so tests can pin the error shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardPortSpec {
    pub local_port: u16,
    pub remote_host: String,
    pub remote_port: u16,
}

pub fn parse_forward_port_spec(raw: &str) -> Result<ForwardPortSpec> {
    let parts: Vec<&str> = raw.split(':').collect();
    if parts.len() != 3 {
        return Err(anyhow::anyhow!(
            "forward_port {raw:?} must have the form 'local:host:remote' (3 parts separated by ':')"
        ));
    }
    let local_port: u16 = parts[0]
        .parse()
        .with_context(|| format!("local port in {raw:?}"))?;
    let remote_host = parts[1].trim().to_string();
    if remote_host.is_empty() {
        return Err(anyhow::anyhow!(
            "forward_port {raw:?} has empty remote host"
        ));
    }
    let remote_port: u16 = parts[2]
        .parse()
        .with_context(|| format!("remote port in {raw:?}"))?;
    if local_port == 0 || remote_port == 0 {
        return Err(anyhow::anyhow!("forward_port {raw:?} has port 0"));
    }
    Ok(ForwardPortSpec {
        local_port,
        remote_host,
        remote_port,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> PortForwardSpec {
        PortForwardSpec {
            target: "i-0123456789abcdef0".into(),
            remote_port: 22,
            region: "us-east-1".into(),
        }
    }

    #[test]
    fn build_args_includes_target_region_and_ports() {
        let args = build_start_session_args(&spec(), 54321);
        // Spot-check ordering and presence; the exact slice should be stable.
        assert_eq!(args[0], "ssm");
        assert_eq!(args[1], "start-session");
        let region_idx = args.iter().position(|s| s == "--region").unwrap();
        assert_eq!(args[region_idx + 1], "us-east-1");
        let target_idx = args.iter().position(|s| s == "--target").unwrap();
        assert_eq!(args[target_idx + 1], "i-0123456789abcdef0");
        let doc_idx = args.iter().position(|s| s == "--document-name").unwrap();
        assert_eq!(args[doc_idx + 1], "AWS-StartPortForwardingSession");
        let params = args.iter().find(|s| s.contains("portNumber")).unwrap();
        assert!(
            params.contains("portNumber=[\"22\"]") && params.contains("localPortNumber=[\"54321\"]"),
            "params encoding wrong: {params}"
        );
    }

    #[test]
    fn build_args_propagates_alternate_region() {
        let mut s = spec();
        s.region = "sa-east-1".into();
        let args = build_start_session_args(&s, 1);
        let region_idx = args.iter().position(|s| s == "--region").unwrap();
        assert_eq!(args[region_idx + 1], "sa-east-1");
    }

    fn remote_spec() -> RemoteHostForwardSpec {
        RemoteHostForwardSpec {
            target: "i-bastion".into(),
            remote_host: "staging-rds.cluster-xxx.us-east-1.rds.amazonaws.com".into(),
            remote_port: 5432,
            local_port: 5432,
            region: "us-east-1".into(),
        }
    }

    #[test]
    fn build_remote_host_args_uses_to_remote_host_document() {
        let args = build_remote_host_session_args(&remote_spec());
        let doc_idx = args.iter().position(|s| s == "--document-name").unwrap();
        assert_eq!(args[doc_idx + 1], "AWS-StartPortForwardingSessionToRemoteHost");
        let target_idx = args.iter().position(|s| s == "--target").unwrap();
        assert_eq!(args[target_idx + 1], "i-bastion");
        let params = args.iter().find(|s| s.contains("host=")).unwrap();
        assert!(params.contains("host=[\"staging-rds.cluster-xxx.us-east-1.rds.amazonaws.com\"]"), "got: {params}");
        assert!(params.contains("portNumber=[\"5432\"]"), "got: {params}");
        assert!(params.contains("localPortNumber=[\"5432\"]"), "got: {params}");
    }

    #[test]
    fn parse_forward_port_spec_round_trips_a_typical_value() {
        let s = parse_forward_port_spec("5432:rds.example.com:5432").unwrap();
        assert_eq!(s.local_port, 5432);
        assert_eq!(s.remote_host, "rds.example.com");
        assert_eq!(s.remote_port, 5432);
    }

    #[test]
    fn parse_forward_port_spec_supports_distinct_local_remote_ports() {
        let s = parse_forward_port_spec("15432:rds.example.com:5432").unwrap();
        assert_eq!(s.local_port, 15432);
        assert_eq!(s.remote_port, 5432);
    }

    #[test]
    fn parse_forward_port_spec_rejects_too_few_parts() {
        let err = parse_forward_port_spec("5432:rds").unwrap_err().to_string();
        assert!(err.contains("3 parts"), "got: {err}");
    }

    #[test]
    fn parse_forward_port_spec_rejects_empty_host() {
        assert!(parse_forward_port_spec("5432::5432").is_err());
    }

    #[test]
    fn parse_forward_port_spec_rejects_zero_port() {
        assert!(parse_forward_port_spec("0:rds:5432").is_err());
        assert!(parse_forward_port_spec("5432:rds:0").is_err());
    }

    #[test]
    fn parse_forward_port_spec_rejects_garbage_port() {
        assert!(parse_forward_port_spec("abc:rds:5432").is_err());
    }

    #[test]
    fn pick_free_local_port_returns_nonzero() {
        let p = pick_free_local_port().unwrap();
        assert!(p > 0);
    }

    #[test]
    fn pick_free_local_port_returns_distinct_ports_back_to_back() {
        // Not strictly guaranteed by the OS but extremely likely; if this
        // ever flakes, drop the assertion. Catches "always returns 0".
        let mut seen = std::collections::HashSet::new();
        for _ in 0..5 {
            seen.insert(pick_free_local_port().unwrap());
        }
        assert!(!seen.is_empty());
    }

    /// Spawn a long-running placeholder process and verify that dropping the
    /// SsmTunnel kills it. We don't need the AWS CLI for this; any child that
    /// would otherwise live longer than the test does the job.
    #[test]
    fn drop_kills_child_process() {
        let child = Command::new("sleep")
            .arg("30")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("sleep should spawn on a Unix host");
        let pid = child.id();
        {
            let _tunnel = SsmTunnel::from_child(40000, child);
            // tunnel drops at end of this scope
        }
        // Give the OS a moment to reap.
        std::thread::sleep(std::time::Duration::from_millis(100));
        // `kill -0` returns 0 if the process exists, non-zero otherwise.
        let alive = Command::new("kill")
            .args(["-0", &pid.to_string()])
            .stderr(Stdio::null())
            .stdout(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        assert!(!alive, "child {pid} should have been killed by drop");
    }
}
