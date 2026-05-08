//! In-memory port registry for active developer tunnels, with disk
//! persistence so the bastion survives a control-plane restart without
//! orphaning sessions.

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Default port range allocated to developer tunnels. Chosen so it doesn't
/// collide with the control-plane port (8443) or with anything privileged.
pub const DEFAULT_PORT_RANGE: PortRange = PortRange {
    start: 10_000,
    end: 19_999,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    pub fn contains(&self, port: u16) -> bool {
        port >= self.start && port <= self.end
    }
}

/// (user, service) tuple keyed in the registry. Stored as a flat string in
/// the on-disk JSON for ease of inspection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Key {
    pub user: String,
    pub service: String,
}

impl Key {
    pub fn new(user: &str, service: &str) -> Self {
        Self {
            user: user.into(),
            service: service.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Registry {
    range: PortRangeOnDisk,
    /// Map (user, service) -> remote_port.
    entries: BTreeMap<String, u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct PortRangeOnDisk {
    start: u16,
    end: u16,
}

impl Default for PortRangeOnDisk {
    fn default() -> Self {
        Self {
            start: DEFAULT_PORT_RANGE.start,
            end: DEFAULT_PORT_RANGE.end,
        }
    }
}

impl Registry {
    pub fn with_range(range: PortRange) -> Self {
        Self {
            range: PortRangeOnDisk {
                start: range.start,
                end: range.end,
            },
            entries: BTreeMap::new(),
        }
    }

    pub fn range(&self) -> PortRange {
        PortRange {
            start: self.range.start,
            end: self.range.end,
        }
    }

    /// Idempotent registration: returns the existing port if the (user,service)
    /// pair already has one, otherwise allocates the lowest free port in the
    /// range. Errors when the range is exhausted.
    pub fn register(&mut self, key: &Key) -> Result<u16> {
        let composite = self.compose_key(key);
        if let Some(&existing) = self.entries.get(&composite) {
            return Ok(existing);
        }
        let port = self.allocate_port()?;
        self.entries.insert(composite, port);
        Ok(port)
    }

    /// Returns the freed port, or `None` if the entry was already absent.
    pub fn deregister(&mut self, key: &Key) -> Option<u16> {
        let composite = self.compose_key(key);
        self.entries.remove(&composite)
    }

    pub fn lookup(&self, key: &Key) -> Option<u16> {
        self.entries.get(&self.compose_key(key)).copied()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Snapshot used by the nginx reloader (commit 9). Sorted for stable
    /// rendering; no internal aliasing.
    pub fn snapshot(&self) -> Vec<(Key, u16)> {
        self.entries
            .iter()
            .filter_map(|(k, &port)| Self::split_key(k).map(|key| (key, port)))
            .collect()
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("creating {}", parent.display()))?;
            }
        }
        let json = serde_json::to_string_pretty(self).context("serializing registry")?;
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, json).with_context(|| format!("writing {}", tmp.display()))?;
        fs::rename(&tmp, path)
            .with_context(|| format!("renaming {} -> {}", tmp.display(), path.display()))?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self> {
        match fs::read_to_string(path) {
            Ok(s) if s.trim().is_empty() => Ok(Self::default()),
            Ok(s) => serde_json::from_str(&s)
                .with_context(|| format!("parsing registry {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("reading registry {}", path.display())),
        }
    }

    fn compose_key(&self, key: &Key) -> String {
        format!("{}/{}", key.user, key.service)
    }

    fn split_key(composite: &str) -> Option<Key> {
        let mut split = composite.splitn(2, '/');
        let user = split.next()?.to_string();
        let service = split.next()?.to_string();
        Some(Key { user, service })
    }

    fn allocate_port(&self) -> Result<u16> {
        let used: std::collections::HashSet<u16> = self.entries.values().copied().collect();
        for port in self.range.start..=self.range.end {
            if !used.contains(&port) {
                return Ok(port);
            }
        }
        Err(anyhow!(
            "port range {}..={} exhausted ({} active sessions)",
            self.range.start,
            self.range.end,
            self.entries.len()
        ))
    }
}

/// Default location: `/var/lib/ephemwork/registry.json`. Override with
/// `EPHEMWORK_REGISTRY_PATH` (used by tests and dev runs).
pub fn default_registry_path() -> PathBuf {
    if let Ok(p) = std::env::var("EPHEMWORK_REGISTRY_PATH") {
        return PathBuf::from(p);
    }
    PathBuf::from("/var/lib/ephemwork/registry.json")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn small_range() -> PortRange {
        PortRange {
            start: 10_000,
            end: 10_002,
        }
    }

    #[test]
    fn register_allocates_lowest_free_port() {
        let mut r = Registry::with_range(small_range());
        assert_eq!(r.register(&Key::new("alice", "api")).unwrap(), 10_000);
        assert_eq!(r.register(&Key::new("bob", "api")).unwrap(), 10_001);
        assert_eq!(r.register(&Key::new("alice", "worker")).unwrap(), 10_002);
    }

    #[test]
    fn register_is_idempotent_per_key() {
        let mut r = Registry::with_range(small_range());
        let p1 = r.register(&Key::new("alice", "api")).unwrap();
        let p2 = r.register(&Key::new("alice", "api")).unwrap();
        assert_eq!(p1, p2);
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn deregister_frees_the_port_for_reuse() {
        let mut r = Registry::with_range(small_range());
        let p1 = r.register(&Key::new("alice", "api")).unwrap();
        assert_eq!(r.deregister(&Key::new("alice", "api")), Some(p1));
        let p2 = r.register(&Key::new("bob", "api")).unwrap();
        assert_eq!(p1, p2, "freed port should be reused");
    }

    #[test]
    fn deregister_returns_none_when_absent() {
        let mut r = Registry::with_range(small_range());
        assert_eq!(r.deregister(&Key::new("ghost", "api")), None);
    }

    #[test]
    fn register_errors_when_range_exhausted() {
        let mut r = Registry::with_range(small_range());
        r.register(&Key::new("a", "x")).unwrap();
        r.register(&Key::new("b", "x")).unwrap();
        r.register(&Key::new("c", "x")).unwrap();
        let err = r.register(&Key::new("d", "x")).unwrap_err().to_string();
        assert!(err.contains("exhausted"), "got: {err}");
    }

    #[test]
    fn lookup_returns_assigned_port() {
        let mut r = Registry::with_range(small_range());
        let p = r.register(&Key::new("alice", "api")).unwrap();
        assert_eq!(r.lookup(&Key::new("alice", "api")), Some(p));
        assert_eq!(r.lookup(&Key::new("alice", "worker")), None);
    }

    #[test]
    fn snapshot_is_stable_and_complete() {
        let mut r = Registry::with_range(small_range());
        r.register(&Key::new("alice", "api")).unwrap();
        r.register(&Key::new("bob", "api")).unwrap();
        let snap = r.snapshot();
        assert_eq!(snap.len(), 2);
        // BTreeMap iteration is sorted by composite key.
        assert_eq!(snap[0].0, Key::new("alice", "api"));
        assert_eq!(snap[1].0, Key::new("bob", "api"));
    }

    #[test]
    fn save_and_load_round_trip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nested/registry.json");
        let mut r = Registry::with_range(small_range());
        r.register(&Key::new("alice", "api")).unwrap();
        r.register(&Key::new("bob", "worker")).unwrap();
        r.save(&path).unwrap();

        let loaded = Registry::load(&path).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded.lookup(&Key::new("alice", "api")), Some(10_000));
        assert_eq!(loaded.lookup(&Key::new("bob", "worker")), Some(10_001));
        assert_eq!(loaded.range(), small_range());
    }

    #[test]
    fn load_missing_file_returns_default() {
        let dir = tempdir().unwrap();
        let r = Registry::load(&dir.path().join("nope.json")).unwrap();
        assert!(r.is_empty());
        assert_eq!(r.range(), DEFAULT_PORT_RANGE);
    }

    #[test]
    fn load_malformed_file_errors() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("bad.json");
        fs::write(&p, "{not json").unwrap();
        assert!(Registry::load(&p).is_err());
    }

    #[test]
    fn save_is_atomic_via_rename() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("registry.json");
        let r = Registry::with_range(small_range());
        r.save(&path).unwrap();
        assert!(!path.with_extension("json.tmp").exists());
    }

    #[test]
    fn port_range_contains_is_inclusive() {
        let r = PortRange { start: 10, end: 20 };
        assert!(r.contains(10));
        assert!(r.contains(20));
        assert!(!r.contains(9));
        assert!(!r.contains(21));
    }
}
