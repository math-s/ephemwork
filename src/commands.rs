//! High-level orchestration for the `up`, `down`, and `status` subcommands.
//!
//! The heavy lifting (config parsing, SSM port-forward, SSH reverse-tunnel,
//! process spawning, health checks, bastion control plane) lives in the
//! sibling modules and is each independently unit-tested. This module is
//! glue: it composes them in the right order, persists the resulting
//! sessions, and produces user-facing output.

use crate::bastion_client::{self, BastionEndpoint};
use crate::bastion_protocol::{DeregisterRequest, RegisterRequest};
use crate::config::{current_user, Config};
use crate::state::{default_state_path, Session, State};
use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use std::path::Path;

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
}
