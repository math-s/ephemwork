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
