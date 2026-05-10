//! Spawn a service and wait for its health endpoint to come up.
//!
//! `run_command` is executed via `sh -c` so that values like
//! `uvicorn app.main:app --reload` work without quoting gymnastics in the
//! TOML config. The returned `RunningService` owns the child and kills it
//! on drop, so a panicking `up` flow never leaves orphaned processes.

use anyhow::{anyhow, Context, Result};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

pub struct RunningService {
    pub pid: u32,
    child: Child,
}

impl RunningService {
    pub fn from_child(child: Child) -> Self {
        Self {
            pid: child.id(),
            child,
        }
    }

    /// Has the child exited on its own? Returns `Some(success)` if exited,
    /// `None` if still running.
    pub fn finished(&mut self) -> std::io::Result<Option<bool>> {
        Ok(self.child.try_wait()?.map(|status| status.success()))
    }
}

impl Drop for RunningService {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Verify that `127.0.0.1:port` is free *right now*. Run at the top of
/// the `up` flow so an orphan listener (e.g. a uvicorn from a previous
/// `ephemwork up` that was killed before its child reaped) surfaces a
/// clear error instead of letting the new spawn fail with a cryptic
/// "address already in use" deep inside uvicorn's startup.
///
/// There's an unavoidable race between this check and the eventual
/// `spawn_service` — another process could grab the port in between —
/// but the common cause (your own previous run) is caught.
pub fn assert_port_free(port: u16) -> Result<()> {
    match TcpListener::bind(("127.0.0.1", port)) {
        Ok(listener) => {
            // Drop immediately so the actual service can bind shortly.
            drop(listener);
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => Err(anyhow!(
            "local port {port} is already in use — likely a leftover \
             process from a previous `ephemwork up` that didn't shut down \
             cleanly.\n\n  \
             Find it:  lsof -nP -iTCP:{port} -sTCP:LISTEN\n  \
             Kill it:  pkill -f \"uvicorn\\|node\\|<your run_command>\"\n  \
             Then re-run ephemwork up."
        )),
        Err(e) => Err(e).with_context(|| format!("probing 127.0.0.1:{port}")),
    }
}

/// Spawn `run_command` via `sh -c`, inheriting the current environment.
/// stdout/stderr go to whatever pipes the caller wants.
pub fn spawn_service(
    run_command: &str,
    stdout: Stdio,
    stderr: Stdio,
) -> Result<RunningService> {
    let child = Command::new("sh")
        .arg("-c")
        .arg(run_command)
        .stdout(stdout)
        .stderr(stderr)
        .spawn()
        .with_context(|| format!("spawning `sh -c {run_command:?}`"))?;
    Ok(RunningService::from_child(child))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthCheck<'a> {
    pub host: &'a str,
    pub port: u16,
    pub path: &'a str,
    pub overall_timeout: Duration,
    pub poll_interval: Duration,
}

/// Poll `host:port/path` until it returns a 2xx status code, or the overall
/// timeout elapses.
pub fn wait_for_health(check: &HealthCheck<'_>) -> Result<u16> {
    let deadline = Instant::now() + check.overall_timeout;
    let mut last_err = None;
    while Instant::now() < deadline {
        let attempt_timeout = check
            .overall_timeout
            .min(Duration::from_secs(2))
            .max(Duration::from_millis(100));
        match http_get_status(check.host, check.port, check.path, attempt_timeout) {
            Ok(code) if (200..300).contains(&code) => return Ok(code),
            Ok(code) => last_err = Some(anyhow!("health check returned status {code}")),
            Err(e) => last_err = Some(e),
        }
        std::thread::sleep(check.poll_interval);
    }
    Err(last_err.unwrap_or_else(|| anyhow!("health check timed out")))
}

/// Minimal HTTP/1.0 GET that returns just the numeric status code. We don't
/// pull in a full HTTP client because health probing is the only need.
pub fn http_get_status(host: &str, port: u16, path: &str, timeout: Duration) -> Result<u16> {
    let addr = (host, port)
        .to_socket_addrs()
        .with_context(|| format!("resolving {host}:{port}"))?
        .next()
        .ok_or_else(|| anyhow!("no addresses for {host}:{port}"))?;
    let mut stream = TcpStream::connect_timeout(&addr, timeout)
        .with_context(|| format!("connecting to {addr}"))?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    write!(
        stream,
        "GET {path} HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    )
    .context("writing GET")?;
    let mut buf = Vec::with_capacity(512);
    stream
        .take(4096)
        .read_to_end(&mut buf)
        .context("reading response")?;
    parse_status_code(&buf)
}

/// Pure parser for the HTTP/1.x status line. Public for testing.
pub fn parse_status_code(response: &[u8]) -> Result<u16> {
    let head = std::str::from_utf8(response).context("response was not valid UTF-8")?;
    let line = head.lines().next().ok_or_else(|| anyhow!("empty response"))?;
    let mut parts = line.split_whitespace();
    let _version = parts.next().ok_or_else(|| anyhow!("missing version"))?;
    let code = parts.next().ok_or_else(|| anyhow!("missing status code"))?;
    code.parse::<u16>()
        .with_context(|| format!("parsing status code {code:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread;

    fn fake_http_server(
        status_line: &'static str,
        body: &'static str,
        max_connections: usize,
    ) -> (u16, Arc<AtomicBool>, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_w = stop.clone();
        let handle = thread::spawn(move || {
            listener.set_nonblocking(true).unwrap();
            let mut served = 0;
            while !stop_w.load(Ordering::SeqCst) && served < max_connections {
                match listener.accept() {
                    Ok((mut s, _)) => {
                        let mut req = [0u8; 1024];
                        let _ = s.read(&mut req);
                        let resp = format!(
                            "{status_line}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = s.write_all(resp.as_bytes());
                        served += 1;
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(20));
                    }
                    Err(_) => break,
                }
            }
        });
        (port, stop, handle)
    }

    #[test]
    fn parse_status_code_happy_path() {
        let resp = b"HTTP/1.0 200 OK\r\n\r\n";
        assert_eq!(parse_status_code(resp).unwrap(), 200);
    }

    #[test]
    fn parse_status_code_handles_404() {
        let resp = b"HTTP/1.1 404 Not Found\r\n\r\n";
        assert_eq!(parse_status_code(resp).unwrap(), 404);
    }

    #[test]
    fn parse_status_code_rejects_empty() {
        assert!(parse_status_code(b"").is_err());
    }

    #[test]
    fn parse_status_code_rejects_garbage() {
        assert!(parse_status_code(b"\xff\xfe nonsense").is_err());
    }

    #[test]
    fn http_get_status_against_local_server() {
        let (port, stop, handle) = fake_http_server("HTTP/1.0 200 OK", "ok", 1);
        let code = http_get_status("127.0.0.1", port, "/health", Duration::from_secs(2)).unwrap();
        assert_eq!(code, 200);
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap();
    }

    #[test]
    fn wait_for_health_succeeds_when_server_is_up() {
        let (port, stop, handle) = fake_http_server("HTTP/1.0 200 OK", "ok", 5);
        let check = HealthCheck {
            host: "127.0.0.1",
            port,
            path: "/health",
            overall_timeout: Duration::from_secs(2),
            poll_interval: Duration::from_millis(50),
        };
        let code = wait_for_health(&check).unwrap();
        assert_eq!(code, 200);
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap();
    }

    #[test]
    fn wait_for_health_returns_error_for_5xx() {
        // Serve 500 indefinitely so polling never sees a connect error; the
        // last reported error must be the 500 itself.
        let (port, stop, handle) = fake_http_server("HTTP/1.0 500 Server Error", "bad", 1_000);
        let check = HealthCheck {
            host: "127.0.0.1",
            port,
            path: "/health",
            overall_timeout: Duration::from_millis(400),
            poll_interval: Duration::from_millis(50),
        };
        let err = wait_for_health(&check).unwrap_err().to_string();
        assert!(err.contains("500"), "got: {err}");
        stop.store(true, Ordering::SeqCst);
        handle.join().unwrap();
    }

    #[test]
    fn wait_for_health_times_out_when_no_server() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        // Drop the listener so the port is closed; connect attempts will fail.
        drop(listener);
        let check = HealthCheck {
            host: "127.0.0.1",
            port,
            path: "/health",
            overall_timeout: Duration::from_millis(300),
            poll_interval: Duration::from_millis(50),
        };
        let err = wait_for_health(&check).unwrap_err().to_string().to_lowercase();
        assert!(
            err.contains("connect")
                || err.contains("refused")
                || err.contains("timed out")
                || err.contains("connection"),
            "got: {err}"
        );
    }

    #[test]
    fn assert_port_free_succeeds_when_port_is_free() {
        // Bind 127.0.0.1:0, capture the port, drop the listener, then
        // probe — the OS may reuse the port before something else grabs
        // it, so the call should succeed.
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        drop(l);
        assert_port_free(port).expect("a just-released port should be probe-free");
    }

    #[test]
    fn assert_port_free_errors_when_port_is_in_use() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let err = assert_port_free(port).unwrap_err().to_string();
        assert!(err.contains("already in use"), "got: {err}");
        assert!(
            err.contains(&port.to_string()) && err.contains("lsof"),
            "expected the message to include the port number and an lsof hint, got:\n{err}"
        );
    }

    #[test]
    fn spawn_service_runs_a_quick_command() {
        let mut svc = spawn_service("true", Stdio::null(), Stdio::null()).unwrap();
        let started = Instant::now();
        loop {
            if let Some(success) = svc.finished().unwrap() {
                assert!(success);
                break;
            }
            assert!(started.elapsed() < Duration::from_secs(2), "command never exited");
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn spawn_service_drop_kills_long_running_child() {
        let svc = spawn_service("sleep 30", Stdio::null(), Stdio::null()).unwrap();
        let pid = svc.pid;
        drop(svc);
        thread::sleep(Duration::from_millis(150));
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
