//! Minimal HTTP/1.0 layer for the bastion control plane.
//!
//! The control plane handles a tiny number of JSON endpoints, so a hand-rolled
//! server keeps the binary small and the dependencies tight (matches the
//! laptop client style). Pure parsing/response building is the testable
//! core; the accept loop is exercised by an integration test.

use anyhow::{anyhow, Context, Result};
use std::io::{Read, Write};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub reason: String,
    pub body: Vec<u8>,
    pub content_type: &'static str,
}

impl Response {
    pub fn json(status: u16, reason: &str, body: impl AsRef<[u8]>) -> Self {
        Self {
            status,
            reason: reason.into(),
            body: body.as_ref().to_vec(),
            content_type: "application/json",
        }
    }

    pub fn text(status: u16, reason: &str, body: impl AsRef<[u8]>) -> Self {
        Self {
            status,
            reason: reason.into(),
            body: body.as_ref().to_vec(),
            content_type: "text/plain",
        }
    }

    pub fn to_wire(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.body.len() + 128);
        let head = format!(
            "HTTP/1.0 {} {}\r\n\
             Content-Type: {}\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n",
            self.status,
            self.reason,
            self.content_type,
            self.body.len()
        );
        out.extend_from_slice(head.as_bytes());
        out.extend_from_slice(&self.body);
        out
    }
}

/// Parse the bytes of an HTTP/1.x request. Tolerant of either bare-LF or CRLF
/// line endings; rejects anything we can't interpret.
pub fn parse_request(raw: &[u8]) -> Result<Request> {
    let split = find_header_terminator(raw)
        .ok_or_else(|| anyhow!("malformed request: no header terminator"))?;
    let head_bytes = &raw[..split.0];
    let body_start = split.1;
    let head = std::str::from_utf8(head_bytes).context("request head not valid UTF-8")?;
    let mut lines = head.split("\r\n").flat_map(|l| l.split('\n'));
    let request_line = lines.next().ok_or_else(|| anyhow!("missing request line"))?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| anyhow!("missing method"))?
        .to_string();
    let path = parts
        .next()
        .ok_or_else(|| anyhow!("missing path"))?
        .to_string();

    let mut content_length: usize = 0;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse().context("parsing content-length")?;
            }
        }
    }
    let body_end = body_start + content_length;
    let body = if body_end <= raw.len() {
        raw[body_start..body_end].to_vec()
    } else {
        raw[body_start..].to_vec()
    };

    Ok(Request {
        method,
        path,
        body,
    })
}

/// Returns `(end_of_head, start_of_body)`. Handles CRLF*2 and LF*2.
fn find_header_terminator(raw: &[u8]) -> Option<(usize, usize)> {
    if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
        return Some((pos, pos + 4));
    }
    if let Some(pos) = raw.windows(2).position(|w| w == b"\n\n") {
        return Some((pos, pos + 2));
    }
    None
}

/// Categorized error from `read_request`. The connection handler logs each
/// variant at the appropriate level — empty connections from health-check
/// probes are noise; truncated or oversized requests from real misuse
/// deserve attention.
#[derive(Debug)]
pub enum RequestError {
    /// Peer closed the connection without sending a single byte. Common
    /// from external port scans / ALB-style TCP-only health probes; not
    /// worth surfacing.
    EmptyConnection,
    /// Some bytes received but the header block didn't terminate before EOF.
    Truncated { bytes: usize },
    /// Request body exceeded the size cap before headers terminated.
    Oversized { cap: usize },
    /// Headers were complete but couldn't be parsed.
    Malformed(anyhow::Error),
    /// Underlying socket I/O failed.
    Io(std::io::Error),
}

impl std::fmt::Display for RequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RequestError::EmptyConnection => write!(f, "peer closed without data"),
            RequestError::Truncated { bytes } => {
                write!(f, "request truncated after {bytes} bytes (no header terminator)")
            }
            RequestError::Oversized { cap } => {
                write!(f, "request exceeded {cap} bytes")
            }
            RequestError::Malformed(e) => write!(f, "malformed: {e}"),
            RequestError::Io(e) => write!(f, "socket I/O: {e}"),
        }
    }
}

impl std::error::Error for RequestError {}

/// Read enough of `stream` to materialize one complete request. Stops at the
/// header terminator or after `Content-Length` body bytes are in hand,
/// whichever is later. Bounded to 64 KiB to avoid OOM on a tiny bastion.
pub fn read_request<S: Read>(stream: &mut S) -> Result<Request, RequestError> {
    const MAX: usize = 64 * 1024;
    let mut buf = Vec::with_capacity(2048);
    let mut tmp = [0u8; 2048];
    loop {
        if buf.len() >= MAX {
            return Err(RequestError::Oversized { cap: MAX });
        }
        let n = stream.read(&mut tmp).map_err(RequestError::Io)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some((_, body_start)) = find_header_terminator(&buf) {
            let head = std::str::from_utf8(&buf[..body_start.saturating_sub(1)]).unwrap_or("");
            let cl: usize = head
                .split('\n')
                .find_map(|l| {
                    let l = l.trim_end_matches('\r');
                    l.split_once(':').and_then(|(k, v)| {
                        if k.eq_ignore_ascii_case("content-length") {
                            v.trim().parse().ok()
                        } else {
                            None
                        }
                    })
                })
                .unwrap_or(0);
            if buf.len() >= body_start + cl {
                break;
            }
        }
    }
    if buf.is_empty() {
        return Err(RequestError::EmptyConnection);
    }
    if find_header_terminator(&buf).is_none() {
        return Err(RequestError::Truncated { bytes: buf.len() });
    }
    parse_request(&buf).map_err(RequestError::Malformed)
}

pub fn write_response<S: Write>(stream: &mut S, response: &Response) -> Result<()> {
    stream
        .write_all(&response.to_wire())
        .context("writing response")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn parse_request_extracts_method_path_body() {
        let raw = b"POST /register HTTP/1.0\r\nHost: x\r\nContent-Length: 11\r\n\r\nhello world";
        let req = parse_request(raw).unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/register");
        assert_eq!(req.body, b"hello world");
    }

    #[test]
    fn parse_request_handles_lf_only_terminator() {
        let raw = b"GET /healthz HTTP/1.0\nHost: x\nContent-Length: 0\n\n";
        let req = parse_request(raw).unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/healthz");
        assert!(req.body.is_empty());
    }

    #[test]
    fn parse_request_tolerates_missing_content_length() {
        let raw = b"GET /healthz HTTP/1.0\r\nHost: x\r\n\r\n";
        let req = parse_request(raw).unwrap();
        assert!(req.body.is_empty());
    }

    #[test]
    fn parse_request_errors_on_no_terminator() {
        let raw = b"POST /register HTTP/1.0\r\nHost: x\r\n";
        assert!(parse_request(raw).is_err());
    }

    #[test]
    fn parse_request_errors_on_garbage() {
        let raw = b"\xff\xfe garbage\r\n\r\n";
        assert!(parse_request(raw).is_err());
    }

    #[test]
    fn response_to_wire_includes_required_headers() {
        let r = Response::json(200, "OK", br#"{"ok":true}"#);
        let s = std::str::from_utf8(&r.to_wire()).unwrap().to_string();
        assert!(s.starts_with("HTTP/1.0 200 OK\r\n"));
        assert!(s.contains("Content-Type: application/json"));
        assert!(s.contains("Content-Length: 11"));
        assert!(s.ends_with(r#"{"ok":true}"#));
    }

    #[test]
    fn response_text_uses_text_plain() {
        let r = Response::text(404, "Not Found", b"nope");
        let s = std::str::from_utf8(&r.to_wire()).unwrap().to_string();
        assert!(s.contains("Content-Type: text/plain"));
    }

    #[test]
    fn read_request_returns_empty_connection_for_zero_bytes() {
        let mut cur = Cursor::new(Vec::new());
        let err = read_request(&mut cur).unwrap_err();
        assert!(matches!(err, RequestError::EmptyConnection), "got: {err:?}");
    }

    #[test]
    fn read_request_returns_truncated_when_eof_before_terminator() {
        // Some bytes but no header terminator before EOF.
        let mut cur = Cursor::new(b"GET /partial HTTP/1.0".to_vec());
        let err = read_request(&mut cur).unwrap_err();
        match err {
            RequestError::Truncated { bytes } => assert!(bytes > 0),
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn read_request_assembles_from_chunks() {
        // Cursor delivers all bytes in one read, but parse_request handles
        // the same wire format we'd see across multiple reads.
        let raw =
            b"POST /register HTTP/1.0\r\nContent-Length: 4\r\n\r\nbody".to_vec();
        let mut cur = Cursor::new(raw);
        let req = read_request(&mut cur).unwrap();
        assert_eq!(req.body, b"body");
    }

    #[test]
    fn read_request_rejects_oversized_input() {
        let mut big = Vec::with_capacity(70 * 1024);
        big.extend_from_slice(b"POST /x HTTP/1.0\r\nContent-Length: 0\r\n");
        // Headers without terminator force the loop to keep reading.
        big.extend(std::iter::repeat(b'A').take(70 * 1024));
        let mut cur = Cursor::new(big);
        match read_request(&mut cur).unwrap_err() {
            RequestError::Oversized { cap } => assert_eq!(cap, 64 * 1024),
            other => panic!("expected Oversized, got {other:?}"),
        }
    }
}
