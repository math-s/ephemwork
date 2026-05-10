use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::{fs, env};

const CONFIG_FILE: &str = "ephemwork.toml";

#[derive(Debug, Deserialize, PartialEq, Eq)]
pub struct Config {
    pub tunnel: TunnelConfig,
    #[serde(default)]
    pub service: HashMap<String, ServiceConfig>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
pub struct TunnelConfig {
    pub r#type: String,
    pub region: String,
    pub instance_type: String,
    /// Project identifier. All bastion AWS resources are named
    /// `ephemwork-{project_name}-bastion[-suffix]` so two projects in the
    /// same AWS account never collide and re-running `bastion init` is
    /// idempotent (the existing instance is reused).
    pub project_name: String,

    /// If set, `bastion init --live` looks up the supplied `--subnet-id`
    /// before creating anything and aborts when the subnet's VPC doesn't
    /// match. Pin this to the staging VPC ID so a misfired init with prod
    /// values cannot accidentally provision a bastion in prod.
    #[serde(default)]
    pub expected_vpc_id: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
pub struct ServiceConfig {
    /// Port the local service listens on. When set, ephemwork tunnels
    /// X-Ephemwork-tagged staging traffic to `127.0.0.1:<port>` via the
    /// bastion. Omit (or set to 0) for a "worker" service that doesn't
    /// receive HTTP — e.g. a local SQS poller. Workers skip the bastion
    /// entirely; ephemwork just runs `bootstrap_command` and
    /// `run_command`.
    #[serde(default)]
    pub port: Option<u16>,
    pub build_command: Option<String>,
    pub run_command: String,
    pub health_check_path: Option<String>,

    /// Outbound forwards opened through the bastion via SSM's
    /// `AWS-StartPortForwardingSessionToRemoteHost` document. Each entry is
    /// `"local_port:remote_host:remote_port"`. The local service can then
    /// reach VPC-private services (staging RDS, ElastiCache, internal APIs)
    /// at `127.0.0.1:<local_port>`.
    #[serde(default)]
    pub forward_ports: Vec<String>,

    /// Optional shell command run before `run_command` on every
    /// `ephemwork up`. Use it to hydrate env files (e.g. fetch staging
    /// credentials from Secrets Manager into `.env.staging`), apply
    /// migrations, or anything else the local service needs in place
    /// before it starts. Runs via `sh -c` and inherits ephemwork's env;
    /// a non-zero exit aborts the up flow before any tunnel is opened.
    pub bootstrap_command: Option<String>,
}

impl Config {
    pub fn load() -> Result<Self> {
        let path = find_config_in(Path::new("."))?;
        let content = fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        let cfg = Self::from_toml_str(&content)
            .with_context(|| format!("parsing {}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn from_toml_str(s: &str) -> Result<Self> {
        toml::from_str(s).map_err(Into::into)
    }

    pub fn validate(&self) -> Result<()> {
        if self.tunnel.r#type.trim().is_empty() {
            return Err(anyhow!("tunnel.type must not be empty"));
        }
        if self.tunnel.region.trim().is_empty() {
            return Err(anyhow!("tunnel.region must not be empty"));
        }
        if self.tunnel.instance_type.trim().is_empty() {
            return Err(anyhow!("tunnel.instance_type must not be empty"));
        }
        if self.tunnel.project_name.trim().is_empty() {
            return Err(anyhow!("tunnel.project_name must not be empty"));
        }
        if !self
            .tunnel
            .project_name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(anyhow!(
                "tunnel.project_name must be ASCII alnum + `-_` (got {:?})",
                self.tunnel.project_name
            ));
        }
        if self.service.is_empty() {
            return Err(anyhow!(
                "at least one [service.<name>] entry is required"
            ));
        }
        for (name, svc) in &self.service {
            if matches!(svc.port, Some(0)) {
                return Err(anyhow!(
                    "service.{name}: port=0 is not valid; omit `port` for a worker service"
                ));
            }
            if svc.run_command.trim().is_empty() {
                return Err(anyhow!("service.{name}: run_command must not be empty"));
            }
            if svc.port.is_none() && !svc.forward_ports.is_empty() {
                return Err(anyhow!(
                    "service.{name}: forward_ports requires `port` (worker services don't open SSM tunnels — run an HTTP service alongside to share its tunnels)"
                ));
            }
        }
        Ok(())
    }
}

fn find_config_in(dir: &Path) -> Result<PathBuf> {
    let path = dir.join(CONFIG_FILE);
    if path.exists() {
        return Ok(path);
    }
    Err(anyhow!(
        "no {CONFIG_FILE} in {}; copy {CONFIG_FILE}.example to get started",
        dir.display()
    ))
}

/// Identity used in the `X-Ephemwork: <user>:<service>` header.
///
/// Resolution order:
///   1. `EPHEMWORK_USER` env var (explicit override)
///   2. local part of `git config user.email`
pub fn current_user() -> Result<String> {
    resolve_user(env::var("EPHEMWORK_USER").ok(), git_user_email)
}

fn git_user_email() -> Result<String> {
    let out = Command::new("git")
        .args(["config", "user.email"])
        .output()
        .context("running `git config user.email`")?;
    if !out.status.success() {
        return Err(anyhow!(
            "git user.email not set; configure it or set EPHEMWORK_USER"
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn resolve_user(
    env_override: Option<String>,
    git_email: impl FnOnce() -> Result<String>,
) -> Result<String> {
    if let Some(u) = env_override {
        let trimmed = u.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }
    let email = git_email()?;
    let local = email.split('@').next().unwrap_or("").trim();
    if local.is_empty() {
        return Err(anyhow!(
            "could not derive a user identity from git user.email; set EPHEMWORK_USER"
        ));
    }
    Ok(local.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    fn valid_toml() -> &'static str {
        r#"
[tunnel]
type = "ec2"
region = "us-east-1"
instance_type = "t4g.nano"
project_name = "demo"

[service.api]
port = 8000
run_command = "uvicorn app.main:app"
health_check_path = "/health"

[service.front-end]
port = 5173
build_command = "npm install"
run_command = "npm run dev"
"#
    }

    #[test]
    fn parses_and_validates_minimal_config() {
        let cfg = Config::from_toml_str(valid_toml()).unwrap();
        assert_eq!(cfg.tunnel.region, "us-east-1");
        assert_eq!(cfg.tunnel.r#type, "ec2");
        assert_eq!(cfg.service["api"].port, Some(8000));
        assert_eq!(cfg.service["api"].health_check_path.as_deref(), Some("/health"));
        assert_eq!(cfg.service["front-end"].build_command.as_deref(), Some("npm install"));
        assert!(cfg.service["front-end"].health_check_path.is_none());
        // expected_vpc_id is optional; the minimal config doesn't set it.
        assert!(cfg.tunnel.expected_vpc_id.is_none());
        cfg.validate().unwrap();
    }

    #[test]
    fn parses_optional_expected_vpc_id() {
        let toml = r#"
[tunnel]
type = "ec2"
region = "us-east-1"
instance_type = "t4g.nano"
project_name = "demo"
expected_vpc_id = "vpc-0123abc"

[service.api]
port = 8000
run_command = "x"
"#;
        let cfg = Config::from_toml_str(toml).unwrap();
        assert_eq!(cfg.tunnel.expected_vpc_id.as_deref(), Some("vpc-0123abc"));
        cfg.validate().unwrap();
    }

    #[test]
    fn validate_rejects_empty_services() {
        let toml = r#"
[tunnel]
type = "ec2"
region = "us-east-1"
instance_type = "t4g.nano"
project_name = "demo"
"#;
        let cfg = Config::from_toml_str(toml).unwrap();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("at least one"), "got: {err}");
    }

    #[test]
    fn validate_rejects_zero_port() {
        // 0 is reserved as a "wrong way to opt into worker mode" — the
        // intended way is to omit the port field entirely.
        let toml = r#"
[tunnel]
type = "ec2"
region = "us-east-1"
instance_type = "t4g.nano"
project_name = "demo"

[service.api]
port = 0
run_command = "x"
"#;
        let cfg = Config::from_toml_str(toml).unwrap();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("omit `port`"), "got: {err}");
    }

    #[test]
    fn parses_worker_service_with_no_port() {
        let toml = r#"
[tunnel]
type = "ec2"
region = "us-east-1"
instance_type = "t4g.nano"
project_name = "demo"

[service.engine-worker]
run_command = "uv run python -m app.lambdas.run_local engine_worker"
"#;
        let cfg = Config::from_toml_str(toml).unwrap();
        assert_eq!(cfg.service["engine-worker"].port, None);
        cfg.validate().unwrap();
    }

    #[test]
    fn validate_rejects_worker_with_forward_ports() {
        let toml = r#"
[tunnel]
type = "ec2"
region = "us-east-1"
instance_type = "t4g.nano"
project_name = "demo"

[service.engine-worker]
run_command = "x"
forward_ports = ["5432:db.example.com:5432"]
"#;
        let cfg = Config::from_toml_str(toml).unwrap();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("forward_ports requires `port`"), "got: {err}");
    }

    #[test]
    fn validate_rejects_empty_run_command() {
        let toml = r#"
[tunnel]
type = "ec2"
region = "us-east-1"
instance_type = "t4g.nano"
project_name = "demo"

[service.api]
port = 8000
run_command = "   "
"#;
        let cfg = Config::from_toml_str(toml).unwrap();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("run_command"), "got: {err}");
    }

    #[test]
    fn validate_rejects_empty_tunnel_field() {
        let toml = r#"
[tunnel]
type = ""
region = "us-east-1"
instance_type = "t4g.nano"
project_name = "demo"

[service.api]
port = 8000
run_command = "x"
"#;
        let cfg = Config::from_toml_str(toml).unwrap();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("tunnel.type"), "got: {err}");
    }

    #[test]
    fn validate_rejects_missing_project_name() {
        // project_name is required by the schema; absence fails parsing.
        let toml = r#"
[tunnel]
type = "ec2"
region = "us-east-1"
instance_type = "t4g.nano"

[service.api]
port = 8000
run_command = "x"
"#;
        assert!(Config::from_toml_str(toml).is_err());
    }

    #[test]
    fn validate_rejects_unsafe_project_name() {
        let toml = r#"
[tunnel]
type = "ec2"
region = "us-east-1"
instance_type = "t4g.nano"
project_name = "moto cred"

[service.api]
port = 8000
run_command = "x"
"#;
        let cfg = Config::from_toml_str(toml).unwrap();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("project_name"), "got: {err}");
    }

    #[test]
    fn parse_fails_on_missing_required_field() {
        let toml = r#"
[tunnel]
type = "ec2"

[service.api]
port = 8000
run_command = "x"
"#;
        assert!(Config::from_toml_str(toml).is_err());
    }

    #[test]
    fn find_config_errors_when_missing() {
        let dir = tempdir().unwrap();
        let err = find_config_in(dir.path()).unwrap_err().to_string();
        assert!(err.contains("no ephemwork.toml"), "got: {err}");
    }

    #[test]
    fn find_config_returns_path_when_present() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(CONFIG_FILE);
        let mut f = fs::File::create(&path).unwrap();
        f.write_all(valid_toml().as_bytes()).unwrap();
        assert_eq!(find_config_in(dir.path()).unwrap(), path);
    }

    #[test]
    fn resolve_user_prefers_env_override() {
        let user = resolve_user(Some("matheus".into()), || {
            panic!("git should not be invoked when env override is set")
        })
        .unwrap();
        assert_eq!(user, "matheus");
    }

    #[test]
    fn resolve_user_trims_env_override() {
        let user = resolve_user(Some("  alice  ".into()), || unreachable!()).unwrap();
        assert_eq!(user, "alice");
    }

    #[test]
    fn resolve_user_falls_through_blank_env_override() {
        let user = resolve_user(Some("   ".into()), || Ok("bob@example.com".into())).unwrap();
        assert_eq!(user, "bob");
    }

    #[test]
    fn resolve_user_uses_email_local_part() {
        let user = resolve_user(None, || Ok("Matheus.Silva@example.com".into())).unwrap();
        assert_eq!(user, "Matheus.Silva");
    }

    #[test]
    fn resolve_user_handles_email_without_at() {
        // git config can return values without an @ sign; treat the whole string as the local part.
        let user = resolve_user(None, || Ok("plainuser".into())).unwrap();
        assert_eq!(user, "plainuser");
    }

    #[test]
    fn resolve_user_errors_on_blank_email() {
        let err = resolve_user(None, || Ok("".into())).unwrap_err().to_string();
        assert!(err.contains("user identity"), "got: {err}");
    }

    #[test]
    fn resolve_user_propagates_git_failure() {
        let err = resolve_user(None, || Err(anyhow!("git not installed")))
            .unwrap_err()
            .to_string();
        assert!(err.contains("git not installed"), "got: {err}");
    }
}
