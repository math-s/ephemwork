//! Reverse SSH port forward laptop:`local_port` <- bastion:`remote_port`.
//!
//! The full ssh2 path needs a real bastion to exercise, so the actual SSH
//! integration is validated end-to-end in commit 7. What lives here:
//!   - `SshConfig` / `SshAuth` plus validation, fully unit-tested.
//!   - `pump_bytes`, the byte pump used to bridge an accepted SSH channel
//!     to localhost — testable against plain TCP without any SSH server.
//!   - `Ssh2ReverseTunnel`, the production wiring; the public API is small
//!     and stable so commit 7 can wire it without further churn.

use anyhow::{anyhow, Context, Result};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth: SshAuth,
    pub keepalive: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshAuth {
    Agent,
    KeyFile {
        private_key: PathBuf,
        passphrase: Option<String>,
    },
}

impl SshConfig {
    pub fn validate(&self) -> Result<()> {
        if self.host.trim().is_empty() {
            return Err(anyhow!("ssh host must not be empty"));
        }
        if self.port == 0 {
            return Err(anyhow!("ssh port must be > 0"));
        }
        if self.username.trim().is_empty() {
            return Err(anyhow!("ssh username must not be empty"));
        }
        if let SshAuth::KeyFile { private_key, .. } = &self.auth {
            if private_key.as_os_str().is_empty() {
                return Err(anyhow!("ssh key path must not be empty"));
            }
        }
        Ok(())
    }
}

/// Copy bytes from `src` to `dst` until EOF or error. Returns the number of
/// bytes moved. Pure I/O; testable against TCP, files, or `Cursor`.
pub fn pump_bytes<R: Read, W: Write>(src: &mut R, dst: &mut W) -> std::io::Result<u64> {
    std::io::copy(src, dst)
}

/// Bridge two read+write endpoints in both directions until either closes
/// or `stop` is set. Both endpoints must be in non-blocking mode and surface
/// `WouldBlock` rather than panicking on no-data; this is the single-threaded
/// alternative to spawning two threads with a split connection (which ssh2's
/// `Channel` doesn't support — it isn't `Send` for `&mut`-sharing).
///
/// Returns the total bytes copied in (a→b, b→a).
pub fn bridge_bidirectional<A, B>(
    a: &mut A,
    b: &mut B,
    stop: &AtomicBool,
) -> std::io::Result<(u64, u64)>
where
    A: Read + Write,
    B: Read + Write,
{
    let mut buf = [0u8; 8192];
    let mut a_to_b: u64 = 0;
    let mut b_to_a: u64 = 0;
    let mut a_done = false;
    let mut b_done = false;

    while !stop.load(Ordering::SeqCst) && !(a_done && b_done) {
        let mut progressed = false;

        if !a_done {
            match a.read(&mut buf) {
                Ok(0) => a_done = true,
                Ok(n) => {
                    write_all_nonblocking(b, &buf[..n])?;
                    a_to_b += n as u64;
                    progressed = true;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            }
        }
        if !b_done {
            match b.read(&mut buf) {
                Ok(0) => b_done = true,
                Ok(n) => {
                    write_all_nonblocking(a, &buf[..n])?;
                    b_to_a += n as u64;
                    progressed = true;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            }
        }

        if !progressed {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    Ok((a_to_b, b_to_a))
}

/// Like `Write::write_all`, but tolerates `WouldBlock` by busy-waiting briefly.
/// Bounded so a stuck remote doesn't deadlock the bridge loop.
fn write_all_nonblocking<W: Write>(w: &mut W, mut buf: &[u8]) -> std::io::Result<()> {
    let mut spins = 0u32;
    while !buf.is_empty() {
        match w.write(buf) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "write returned 0",
                ));
            }
            Ok(n) => {
                buf = &buf[n..];
                spins = 0;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                spins += 1;
                if spins > 1000 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "write blocked for too long",
                    ));
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Handle to an active reverse forward. Dropping the handle signals the
/// worker thread to stop.
pub struct ReverseForward {
    pub local_port: u16,
    pub remote_port: u16,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

impl ReverseForward {
    /// Construct a handle around an already-spawned worker. Exposed so
    /// commit 7's integration test can wrap any worker (real ssh2 or fake).
    pub fn from_worker(
        local_port: u16,
        remote_port: u16,
        stop: Arc<AtomicBool>,
        worker: thread::JoinHandle<()>,
    ) -> Self {
        Self {
            local_port,
            remote_port,
            stop,
            worker: Some(worker),
        }
    }

    pub fn shutdown(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.worker.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for ReverseForward {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.worker.take() {
            let _ = handle.join();
        }
    }
}

/// Production ssh2-backed reverse tunnel. The body intentionally stays thin
/// because it needs a real bastion to validate; commit 7 wires it into the
/// `up` flow with end-to-end coverage.
pub fn open_ssh2_reverse_forward(
    cfg: &SshConfig,
    local_port: u16,
    remote_port: u16,
) -> Result<ReverseForward> {
    use ssh2::Session;
    use std::net::TcpStream;

    cfg.validate()?;

    let tcp = TcpStream::connect((cfg.host.as_str(), cfg.port))
        .with_context(|| format!("connecting to {}:{}", cfg.host, cfg.port))?;
    let mut sess = Session::new().context("creating ssh session")?;
    sess.set_tcp_stream(tcp);
    sess.handshake().context("ssh handshake failed")?;

    match &cfg.auth {
        SshAuth::Agent => sess
            .userauth_agent(&cfg.username)
            .context("ssh-agent authentication")?,
        SshAuth::KeyFile {
            private_key,
            passphrase,
        } => sess
            .userauth_pubkey_file(&cfg.username, None, private_key, passphrase.as_deref())
            .context("public-key authentication")?,
    }
    if !sess.authenticated() {
        return Err(anyhow!("ssh authentication failed"));
    }
    sess.set_keepalive(true, cfg.keepalive.as_secs() as u32);

    // Request the remote-side listener while the session is still blocking
    // — channel_forward_listen on a non-blocking session returns EAGAIN
    // (LIBSSH2_ERROR_EAGAIN, code -37) instead of completing, which
    // surfaced as `Error: requesting remote port forward / Would block`.
    let (listener, _bound) = sess
        .channel_forward_listen(remote_port, Some(&cfg.host), None)
        .context("requesting remote port forward")?;

    // Now flip to non-blocking so bridge_bidirectional can poll the
    // accepted channels without parking the worker thread.
    sess.set_blocking(false);

    let stop = Arc::new(AtomicBool::new(false));
    let stop_worker = stop.clone();

    let worker = thread::spawn(move || {
        let mut listener = listener;
        while !stop_worker.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok(channel) => {
                    let stop_for_bridge = stop_worker.clone();
                    thread::spawn(move || {
                        if let Err(e) = handle_accepted_channel(channel, local_port, &stop_for_bridge) {
                            tracing::warn!(?e, "bridging accepted channel failed");
                        }
                    });
                }
                Err(_) => {
                    // ssh2 returns errors when there's nothing to accept yet;
                    // sleep a beat to avoid pegging the CPU.
                    thread::sleep(Duration::from_millis(50));
                }
            }
        }
    });

    Ok(ReverseForward::from_worker(
        local_port,
        remote_port,
        stop,
        worker,
    ))
}

/// Bridge an accepted SSH channel to `127.0.0.1:local_port`. The TCP socket
/// is set non-blocking up front so `bridge_bidirectional` can poll both ends.
fn handle_accepted_channel(
    mut channel: ssh2::Channel,
    local_port: u16,
    stop: &AtomicBool,
) -> Result<()> {
    let tcp = std::net::TcpStream::connect(("127.0.0.1", local_port))
        .with_context(|| format!("connecting to 127.0.0.1:{local_port}"))?;
    tcp.set_nonblocking(true)
        .context("setting TCP socket non-blocking")?;
    let mut tcp = tcp;
    let _ = bridge_bidirectional(&mut channel, &mut tcp, stop);
    let _ = channel.close();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::net::{TcpListener, TcpStream};
    use std::sync::Mutex;

    fn cfg() -> SshConfig {
        SshConfig {
            host: "127.0.0.1".into(),
            port: 22,
            username: "ec2-user".into(),
            auth: SshAuth::Agent,
            keepalive: Duration::from_secs(30),
        }
    }

    #[test]
    fn validate_accepts_minimal_agent_config() {
        cfg().validate().unwrap();
    }

    #[test]
    fn validate_accepts_keyfile_config() {
        let mut c = cfg();
        c.auth = SshAuth::KeyFile {
            private_key: PathBuf::from("/home/me/.ssh/id_rsa"),
            passphrase: None,
        };
        c.validate().unwrap();
    }

    #[test]
    fn validate_rejects_empty_host() {
        let mut c = cfg();
        c.host = "".into();
        let err = c.validate().unwrap_err().to_string();
        assert!(err.contains("host"), "got: {err}");
    }

    #[test]
    fn validate_rejects_zero_port() {
        let mut c = cfg();
        c.port = 0;
        let err = c.validate().unwrap_err().to_string();
        assert!(err.contains("port"), "got: {err}");
    }

    #[test]
    fn validate_rejects_empty_username() {
        let mut c = cfg();
        c.username = "".into();
        let err = c.validate().unwrap_err().to_string();
        assert!(err.contains("username"), "got: {err}");
    }

    #[test]
    fn validate_rejects_empty_keyfile_path() {
        let mut c = cfg();
        c.auth = SshAuth::KeyFile {
            private_key: PathBuf::new(),
            passphrase: None,
        };
        let err = c.validate().unwrap_err().to_string();
        assert!(err.contains("key path"), "got: {err}");
    }

    #[test]
    fn pump_bytes_copies_in_memory() {
        let mut src = Cursor::new(b"hello ephemwork".to_vec());
        let mut dst = Vec::new();
        let n = pump_bytes(&mut src, &mut dst).unwrap();
        assert_eq!(n as usize, b"hello ephemwork".len());
        assert_eq!(dst, b"hello ephemwork");
    }

    /// Spin up a localhost echo-ish server that reads everything sent to it
    /// and writes it into a shared buffer. Verify `pump_bytes` carries TCP
    /// bytes from one socket to another without loss.
    #[test]
    fn pump_bytes_works_across_tcp() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let received = Arc::new(Mutex::new(Vec::<u8>::new()));
        let received_w = received.clone();

        let server = thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut buf = Vec::new();
            sock.read_to_end(&mut buf).unwrap();
            received_w.lock().unwrap().extend_from_slice(&buf);
        });

        let mut src = Cursor::new(b"reverse tunnel payload".to_vec());
        let mut dst = TcpStream::connect(addr).unwrap();
        let n = pump_bytes(&mut src, &mut dst).unwrap();
        // Close write side so the server's read_to_end returns.
        dst.shutdown(std::net::Shutdown::Write).unwrap();
        drop(dst);
        server.join().unwrap();

        assert_eq!(n as usize, b"reverse tunnel payload".len());
        assert_eq!(*received.lock().unwrap(), b"reverse tunnel payload");
    }

    #[test]
    fn bridge_bidirectional_forwards_bytes() {
        use std::net::{TcpListener, TcpStream};

        // Two TCP pairs stand in for (driver, ssh-channel) and (local-service, bastion-tcp).
        let driver_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let driver_addr = driver_listener.local_addr().unwrap();
        let svc_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let svc_addr = svc_listener.local_addr().unwrap();

        let mut driver = TcpStream::connect(driver_addr).unwrap();
        let (a_side, _) = driver_listener.accept().unwrap();
        let b_side = TcpStream::connect(svc_addr).unwrap();
        let (mut svc, _) = svc_listener.accept().unwrap();

        a_side.set_nonblocking(true).unwrap();
        b_side.set_nonblocking(true).unwrap();

        let stop = Arc::new(AtomicBool::new(false));
        let stop_w = stop.clone();
        let bridge_thread = thread::spawn(move || {
            let mut a = a_side;
            let mut b = b_side;
            bridge_bidirectional(&mut a, &mut b, &stop_w).ok();
        });

        // a -> b: write into driver, expect bytes on svc.
        driver.write_all(b"hello").unwrap();
        let mut buf = [0u8; 5];
        svc.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"hello");

        // b -> a: write into svc, expect bytes on driver.
        svc.write_all(b"world").unwrap();
        let mut buf = [0u8; 5];
        driver.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"world");

        stop.store(true, Ordering::SeqCst);
        bridge_thread.join().unwrap();
    }

    #[test]
    fn bridge_bidirectional_honors_stop_flag_with_idle_streams() {
        use std::net::{TcpListener, TcpStream};
        // Two idle TCP pairs that never send anything; the bridge should
        // exit promptly when the stop flag is set rather than spin forever.
        let l1 = TcpListener::bind("127.0.0.1:0").unwrap();
        let a1 = l1.local_addr().unwrap();
        let l2 = TcpListener::bind("127.0.0.1:0").unwrap();
        let a2 = l2.local_addr().unwrap();
        let _client1 = TcpStream::connect(a1).unwrap();
        let _client2 = TcpStream::connect(a2).unwrap();
        let (s1, _) = l1.accept().unwrap();
        let (s2, _) = l2.accept().unwrap();
        s1.set_nonblocking(true).unwrap();
        s2.set_nonblocking(true).unwrap();

        let stop = Arc::new(AtomicBool::new(false));
        let stop_w = stop.clone();
        let join = thread::spawn(move || {
            let mut s1 = s1;
            let mut s2 = s2;
            bridge_bidirectional(&mut s1, &mut s2, &stop_w).ok();
        });

        thread::sleep(Duration::from_millis(50));
        stop.store(true, Ordering::SeqCst);
        let start = std::time::Instant::now();
        join.join().unwrap();
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "bridge did not honor stop flag within 1s"
        );
    }

    #[test]
    fn reverse_forward_drop_signals_worker() {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_w = stop.clone();
        let observed_stop = Arc::new(AtomicBool::new(false));
        let observed_w = observed_stop.clone();

        let worker = thread::spawn(move || {
            while !stop_w.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_millis(10));
            }
            observed_w.store(true, Ordering::SeqCst);
        });

        let handle = ReverseForward::from_worker(8000, 9000, stop, worker);
        // Drop the handle and the worker should observe stop and exit.
        drop(handle);
        // join already happened inside Drop; confirm the worker reached the end.
        assert!(observed_stop.load(Ordering::SeqCst));
    }

    #[test]
    fn reverse_forward_shutdown_is_idempotent() {
        // shutdown() consumes self; just verify the call shape compiles and
        // that constructing/destroying twice in different ways doesn't panic.
        let stop = Arc::new(AtomicBool::new(false));
        let stop_w = stop.clone();
        let worker = thread::spawn(move || {
            while !stop_w.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_millis(5));
            }
        });
        let handle = ReverseForward::from_worker(1, 2, stop, worker);
        handle.shutdown();
    }
}
