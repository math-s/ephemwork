use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Session {
    pub user: String,
    pub service: String,
    pub started_at: DateTime<Utc>,
    pub local_port: u16,
    pub remote_port: u16,
    pub pid: Option<u32>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct State {
    #[serde(default)]
    pub sessions: Vec<Session>,
}

impl State {
    /// Load state from `path`. A missing file yields an empty `State` so first
    /// runs Just Work. A malformed file is an error so we don't silently lose
    /// active sessions.
    pub fn load(path: &Path) -> Result<Self> {
        match fs::read_to_string(path) {
            Ok(s) if s.trim().is_empty() => Ok(Self::default()),
            Ok(s) => serde_json::from_str(&s)
                .with_context(|| format!("parsing state file {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("reading state file {}", path.display())),
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("creating {}", parent.display()))?;
            }
        }
        let json = serde_json::to_string_pretty(self).context("serializing state")?;
        // Write to a sibling temp file then rename for atomicity.
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, json).with_context(|| format!("writing {}", tmp.display()))?;
        fs::rename(&tmp, path)
            .with_context(|| format!("renaming {} -> {}", tmp.display(), path.display()))?;
        Ok(())
    }

    /// Add a session, replacing any existing one with the same (user, service).
    pub fn upsert(&mut self, session: Session) {
        self.sessions
            .retain(|s| !(s.user == session.user && s.service == session.service));
        self.sessions.push(session);
    }

    /// Remove sessions matching the predicate; returns the removed entries.
    pub fn remove_where<F>(&mut self, mut pred: F) -> Vec<Session>
    where
        F: FnMut(&Session) -> bool,
    {
        let mut removed = Vec::new();
        let mut keep = Vec::with_capacity(self.sessions.len());
        for s in self.sessions.drain(..) {
            if pred(&s) {
                removed.push(s);
            } else {
                keep.push(s);
            }
        }
        self.sessions = keep;
        removed
    }

    pub fn for_user<'a>(&'a self, user: &'a str) -> impl Iterator<Item = &'a Session> + 'a {
        self.sessions.iter().filter(move |s| s.user == user)
    }
}

/// Default location: `$HOME/.ephemwork/state.json`. Override with
/// `EPHEMWORK_STATE_DIR` (used by tests).
pub fn default_state_path() -> Result<PathBuf> {
    if let Ok(dir) = std::env::var("EPHEMWORK_STATE_DIR") {
        return Ok(PathBuf::from(dir).join("state.json"));
    }
    let home = std::env::var("HOME").context("HOME not set")?;
    Ok(PathBuf::from(home).join(".ephemwork").join("state.json"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use tempfile::tempdir;

    fn fixed_time() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 5, 8, 12, 0, 0).unwrap()
    }

    fn sample(user: &str, service: &str, port: u16) -> Session {
        Session {
            user: user.into(),
            service: service.into(),
            started_at: fixed_time(),
            local_port: port,
            remote_port: 9000 + port,
            pid: Some(1234),
        }
    }

    #[test]
    fn load_missing_returns_empty() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nope.json");
        let state = State::load(&path).unwrap();
        assert!(state.sessions.is_empty());
    }

    #[test]
    fn load_empty_file_returns_empty() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("empty.json");
        fs::write(&path, "").unwrap();
        let state = State::load(&path).unwrap();
        assert!(state.sessions.is_empty());
    }

    #[test]
    fn load_malformed_file_errors() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("bad.json");
        fs::write(&path, "{not json").unwrap();
        assert!(State::load(&path).is_err());
    }

    #[test]
    fn save_creates_parent_directory() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nested/deeper/state.json");
        let mut state = State::default();
        state.upsert(sample("alice", "api", 8000));
        state.save(&path).unwrap();
        assert!(path.exists());
        let reloaded = State::load(&path).unwrap();
        assert_eq!(reloaded, state);
    }

    #[test]
    fn upsert_replaces_existing_session() {
        let mut state = State::default();
        state.upsert(sample("alice", "api", 8000));
        let mut updated = sample("alice", "api", 9999);
        updated.remote_port = 22222;
        state.upsert(updated.clone());
        assert_eq!(state.sessions.len(), 1);
        assert_eq!(state.sessions[0], updated);
    }

    #[test]
    fn upsert_keeps_distinct_services() {
        let mut state = State::default();
        state.upsert(sample("alice", "api", 8000));
        state.upsert(sample("alice", "worker", 8001));
        assert_eq!(state.sessions.len(), 2);
    }

    #[test]
    fn upsert_keeps_distinct_users() {
        let mut state = State::default();
        state.upsert(sample("alice", "api", 8000));
        state.upsert(sample("bob", "api", 8000));
        assert_eq!(state.sessions.len(), 2);
    }

    #[test]
    fn remove_where_returns_removed() {
        let mut state = State::default();
        state.upsert(sample("alice", "api", 8000));
        state.upsert(sample("alice", "worker", 8001));
        let removed = state.remove_where(|s| s.service == "api");
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].service, "api");
        assert_eq!(state.sessions.len(), 1);
        assert_eq!(state.sessions[0].service, "worker");
    }

    #[test]
    fn for_user_filters() {
        let mut state = State::default();
        state.upsert(sample("alice", "api", 8000));
        state.upsert(sample("bob", "api", 8001));
        let alice: Vec<_> = state.for_user("alice").collect();
        assert_eq!(alice.len(), 1);
        assert_eq!(alice[0].user, "alice");
    }

    #[test]
    fn save_is_atomic_via_rename() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("state.json");
        let mut state = State::default();
        state.upsert(sample("alice", "api", 8000));
        state.save(&path).unwrap();
        // The temp file must not linger after a successful save.
        assert!(!path.with_extension("json.tmp").exists());
    }

    #[test]
    fn default_state_path_respects_override() {
        let prev = std::env::var("EPHEMWORK_STATE_DIR").ok();
        std::env::set_var("EPHEMWORK_STATE_DIR", "/tmp/ephem-test");
        let path = default_state_path().unwrap();
        assert_eq!(path, PathBuf::from("/tmp/ephem-test/state.json"));
        match prev {
            Some(v) => std::env::set_var("EPHEMWORK_STATE_DIR", v),
            None => std::env::remove_var("EPHEMWORK_STATE_DIR"),
        }
    }
}
