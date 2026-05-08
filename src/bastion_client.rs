//! Tiny HTTP client for the bastion control plane.
//!
//! Hand-rolled HTTP/1.0 because the only operations are JSON POST to known
//! endpoints; pulling in `reqwest` would be a lot of dependency for two
//! requests. The pure parts (request building, response parsing) are
//! unit-tested; the network round-trip is verified against an in-process
//! fake server.

use crate::bastion_protocol::{DeregisterRequest, RegisterRequest, RegisterResponse};
use anyhow::{anyhow, Context, Result};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

/// Where the laptop sends control-plane requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BastionEndpoint {
    pub host: String,
    pub port: u16,
}

impl BastionEndpoint {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }
}

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

pub fn register(
    endpoint: &BastionEndpoint,
    req: &RegisterRequest,
) -> Result<RegisterResponse> {
    let body = serde_json::to_vec(req).context("encoding register request")?;
    let response = post_json(endpoint, "/register", &body, DEFAULT_TIMEOUT)?;
    let parsed: RegisterResponse =
        serde_json::from_slice(&response.body).context("decoding register response")?;
    Ok(parsed)
}

pub fn deregister(endpoint: &BastionEndpoint, req: &DeregisterRequest) -> Result<()> {
    let body = serde_json::to_vec(req).context("encoding deregister request")?;
    let _ = post_json(endpoint, "/deregister", &body, DEFAULT_TIMEOUT)?;
    Ok(())
}

#[derive(Debug)]
struct HttpResponse {
    status: u16,
    body: Vec<u8>,
}

fn post_json(
    endpoint: &BastionEndpoint,
    path: &str,
    body: &[u8],
    timeout: Duration,
) -> Result<HttpResponse> {
    let addr = (endpoint.host.as_str(), endpoint.port)
        .to_socket_addrs()
        .with_context(|| format!("resolving {}:{}", endpoint.host, endpoint.port))?
        .next()
        .ok_or_else(|| anyhow!("no addresses for {}:{}", endpoint.host, endpoint.port))?;
    let mut stream = TcpStream::connect_timeout(&addr, timeout)
        .with_context(|| format!("connecting to {addr}"))?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    let request = build_request(&endpoint.host, path, body);
    stream.write_all(&request).context("writing request")?;
    let mut buf = Vec::with_capacity(512);
    stream.read_to_end(&mut buf).context("reading response")?;
    let parsed = parse_response(&buf)?;
    if !(200..300).contains(&parsed.status) {
        return Err(anyhow!(
            "bastion returned status {}: {}",
            parsed.status,
            String::from_utf8_lossy(&parsed.body)
        ));
    }
    Ok(parsed)
}

/// Pure constructor for the wire bytes of a JSON POST. Public for tests.
pub fn build_request(host: &str, path: &str, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 256);
    let head = format!(
        "POST {path} HTTP/1.0\r\n\
         Host: {host}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    out.extend_from_slice(head.as_bytes());
    out.extend_from_slice(body);
    out
}

fn parse_response(raw: &[u8]) -> Result<HttpResponse> {
    let split = find_double_crlf(raw).ok_or_else(|| anyhow!("malformed http response: no header terminator"))?;
    let head = std::str::from_utf8(&raw[..split]).context("response head was not valid UTF-8")?;
    let status_line = head.lines().next().ok_or_else(|| anyhow!("missing status line"))?;
    let mut parts = status_line.split_whitespace();
    let _version = parts.next();
    let status: u16 = parts
        .next()
        .ok_or_else(|| anyhow!("missing status code"))?
        .parse()
        .context("parsing status code")?;
    let body = raw[split + 4..].to_vec();
    Ok(HttpResponse { status, body })
}

fn find_double_crlf(raw: &[u8]) -> Option<usize> {
    raw.windows(4).position(|w| w == b"\r\n\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread;

    /// Spin up a fake server that handles a single POST and replies with the
    /// given status + JSON body. Returns the port and the captured request.
    fn fake_bastion(
        status_line: &'static str,
        json: &'static str,
    ) -> (u16, Arc<std::sync::Mutex<Vec<u8>>>, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let captured = Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let captured_w = captured.clone();
        let handle = thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut buf = [0u8; 4096];
            // Read until we have headers + content-length bytes; for tests
            // we accept anything available within the timeout.
            let n = sock.read(&mut buf).unwrap_or(0);
            captured_w.lock().unwrap().extend_from_slice(&buf[..n]);
            let resp = format!(
                "{status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{json}",
                json.len()
            );
            sock.write_all(resp.as_bytes()).unwrap();
        });
        (port, captured, handle)
    }

    #[test]
    fn build_request_includes_required_headers() {
        let req = build_request("bastion.local", "/register", br#"{"user":"a"}"#);
        let s = std::str::from_utf8(&req).unwrap();
        assert!(s.starts_with("POST /register HTTP/1.0"));
        assert!(s.contains("Host: bastion.local"));
        assert!(s.contains("Content-Type: application/json"));
        assert!(s.contains("Content-Length: 12"));
        assert!(s.ends_with(r#"{"user":"a"}"#));
    }

    #[test]
    fn parse_response_extracts_status_and_body() {
        let raw = b"HTTP/1.0 200 OK\r\nContent-Length: 4\r\n\r\nbody";
        let r = parse_response(raw).unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.body, b"body");
    }

    #[test]
    fn parse_response_rejects_missing_terminator() {
        let raw = b"HTTP/1.0 200 OK\r\nContent-Length: 4\r\n";
        assert!(parse_response(raw).is_err());
    }

    #[test]
    fn parse_response_rejects_garbage_status() {
        let raw = b"HTTP/1.0 abc Bad\r\n\r\nbody";
        assert!(parse_response(raw).is_err());
    }

    #[test]
    fn register_round_trips_against_fake_server() {
        let (port, captured, handle) = fake_bastion("HTTP/1.0 200 OK", r#"{"remote_port":9001}"#);
        let endpoint = BastionEndpoint::new("127.0.0.1", port);
        let req = RegisterRequest {
            user: "matheus".into(),
            service: "api".into(),
        };
        let resp = register(&endpoint, &req).unwrap();
        assert_eq!(resp.remote_port, 9001);
        handle.join().unwrap();

        let captured = captured.lock().unwrap();
        let s = std::str::from_utf8(&captured).unwrap();
        assert!(s.contains("POST /register"));
        assert!(s.contains(r#""user":"matheus""#));
        assert!(s.contains(r#""service":"api""#));
    }

    #[test]
    fn deregister_round_trips_against_fake_server() {
        let (port, _captured, handle) = fake_bastion("HTTP/1.0 200 OK", "{}");
        let endpoint = BastionEndpoint::new("127.0.0.1", port);
        deregister(
            &endpoint,
            &DeregisterRequest {
                user: "matheus".into(),
                service: "api".into(),
            },
        )
        .unwrap();
        handle.join().unwrap();
    }

    #[test]
    fn register_propagates_5xx() {
        let (port, _captured, handle) = fake_bastion("HTTP/1.0 500 Boom", r#"{"error":"boom"}"#);
        let endpoint = BastionEndpoint::new("127.0.0.1", port);
        let err = register(
            &endpoint,
            &RegisterRequest {
                user: "x".into(),
                service: "y".into(),
            },
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("500"), "got: {err}");
        assert!(err.contains("boom"), "got: {err}");
        handle.join().unwrap();
    }

    #[test]
    fn register_errors_on_bad_json() {
        let (port, _captured, handle) = fake_bastion("HTTP/1.0 200 OK", "not json");
        let endpoint = BastionEndpoint::new("127.0.0.1", port);
        let err = register(
            &endpoint,
            &RegisterRequest {
                user: "x".into(),
                service: "y".into(),
            },
        )
        .unwrap_err()
        .to_string();
        assert!(err.to_lowercase().contains("decoding"), "got: {err}");
        handle.join().unwrap();
    }

    // suppress unused import warnings on no-op atomic helper if not used
    #[allow(dead_code)]
    fn _unused(_a: AtomicBool) {}
    #[allow(dead_code)]
    fn _unused2(_a: Arc<()>) {}
    #[allow(dead_code)]
    fn _unused3(_a: Ordering) {}
}
