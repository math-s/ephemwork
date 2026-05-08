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
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
pub struct ServiceConfig {
    pub port: u16,
    pub build_command: Option<String>,
    pub run_command: String,
    pub health_check_path: Option<String>,
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
        if self.service.is_empty() {
            return Err(anyhow!(
                "at least one [service.<name>] entry is required"
            ));
        }
        for (name, svc) in &self.service {
            if svc.port == 0 {
                return Err(anyhow!("service.{name}: port must be > 0"));
            }
            if svc.run_command.trim().is_empty() {
                return Err(anyhow!("service.{name}: run_command must not be empty"));
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
        assert_eq!(cfg.service["api"].port, 8000);
        assert_eq!(cfg.service["api"].health_check_path.as_deref(), Some("/health"));
        assert_eq!(cfg.service["front-end"].build_command.as_deref(), Some("npm install"));
        assert!(cfg.service["front-end"].health_check_path.is_none());
        cfg.validate().unwrap();
    }

    #[test]
    fn validate_rejects_empty_services() {
        let toml = r#"
[tunnel]
type = "ec2"
region = "us-east-1"
instance_type = "t4g.nano"
"#;
        let cfg = Config::from_toml_str(toml).unwrap();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("at least one"), "got: {err}");
    }

    #[test]
    fn validate_rejects_zero_port() {
        let toml = r#"
[tunnel]
type = "ec2"
region = "us-east-1"
instance_type = "t4g.nano"

[service.api]
port = 0
run_command = "x"
"#;
        let cfg = Config::from_toml_str(toml).unwrap();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("port must be > 0"), "got: {err}");
    }

    #[test]
    fn validate_rejects_empty_run_command() {
        let toml = r#"
[tunnel]
type = "ec2"
region = "us-east-1"
instance_type = "t4g.nano"

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

[service.api]
port = 8000
run_command = "x"
"#;
        let cfg = Config::from_toml_str(toml).unwrap();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("tunnel.type"), "got: {err}");
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
