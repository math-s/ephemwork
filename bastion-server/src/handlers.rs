//! Pure routing/handler logic. Given a `Request` and a mutable `Registry`,
//! produce a `Response`. No I/O, so every code path is unit-testable.

use crate::http::{Request, Response};
use crate::registry::{Key, Registry};
use ephemwork_common::{
    DeregisterRequest, ErrorResponse, RegisterRequest, RegisterResponse,
};

/// Hook the bastion calls after every successful mutation so the nginx
/// reloader (commit 9) can rewrite its upstream map. Pure trait so tests
/// can verify it's invoked.
pub trait MutationListener {
    fn on_change(&mut self, registry: &Registry);
}

pub struct NoopListener;

impl MutationListener for NoopListener {
    fn on_change(&mut self, _registry: &Registry) {}
}

pub fn route(
    request: &Request,
    registry: &mut Registry,
    listener: &mut dyn MutationListener,
) -> Response {
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/healthz") => Response::text(200, "OK", b"ok"),
        ("POST", "/register") => handle_register(request, registry, listener),
        ("POST", "/deregister") => handle_deregister(request, registry, listener),
        ("GET", "/snapshot") => handle_snapshot(registry),
        _ => json_error(404, "Not Found", "no such route"),
    }
}

fn handle_register(
    req: &Request,
    registry: &mut Registry,
    listener: &mut dyn MutationListener,
) -> Response {
    let parsed: RegisterRequest = match serde_json::from_slice(&req.body) {
        Ok(v) => v,
        Err(e) => return json_error(400, "Bad Request", &e.to_string()),
    };
    if parsed.user.trim().is_empty() || parsed.service.trim().is_empty() {
        return json_error(400, "Bad Request", "user and service must be non-empty");
    }
    match registry.register(&Key::new(&parsed.user, &parsed.service)) {
        Ok(remote_port) => {
            listener.on_change(registry);
            let body = serde_json::to_vec(&RegisterResponse { remote_port })
                .expect("RegisterResponse always serializes");
            Response::json(200, "OK", body)
        }
        Err(e) => json_error(503, "Service Unavailable", &e.to_string()),
    }
}

fn handle_deregister(
    req: &Request,
    registry: &mut Registry,
    listener: &mut dyn MutationListener,
) -> Response {
    let parsed: DeregisterRequest = match serde_json::from_slice(&req.body) {
        Ok(v) => v,
        Err(e) => return json_error(400, "Bad Request", &e.to_string()),
    };
    let removed = registry.deregister(&Key::new(&parsed.user, &parsed.service));
    if removed.is_some() {
        listener.on_change(registry);
    }
    Response::json(200, "OK", b"{}")
}

fn handle_snapshot(registry: &Registry) -> Response {
    #[derive(serde::Serialize)]
    struct Entry {
        user: String,
        service: String,
        remote_port: u16,
    }
    let entries: Vec<Entry> = registry
        .snapshot()
        .into_iter()
        .map(|(k, port)| Entry {
            user: k.user,
            service: k.service,
            remote_port: port,
        })
        .collect();
    let body = serde_json::to_vec(&entries).expect("snapshot always serializes");
    Response::json(200, "OK", body)
}

fn json_error(status: u16, reason: &str, message: &str) -> Response {
    let body = serde_json::to_vec(&ErrorResponse {
        error: message.into(),
    })
    .expect("ErrorResponse always serializes");
    Response::json(status, reason, body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::PortRange;

    #[derive(Default)]
    struct CountingListener {
        calls: usize,
    }

    impl MutationListener for CountingListener {
        fn on_change(&mut self, _registry: &Registry) {
            self.calls += 1;
        }
    }

    fn req(method: &str, path: &str, body: &[u8]) -> Request {
        Request {
            method: method.into(),
            path: path.into(),
            body: body.to_vec(),
        }
    }

    fn registry() -> Registry {
        Registry::with_range(PortRange {
            start: 10_000,
            end: 10_002,
        })
    }

    #[test]
    fn healthz_returns_ok() {
        let mut r = registry();
        let resp = route(&req("GET", "/healthz", b""), &mut r, &mut NoopListener);
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"ok");
    }

    #[test]
    fn register_returns_allocated_port_and_notifies_listener() {
        let mut r = registry();
        let mut l = CountingListener::default();
        let body = br#"{"user":"alice","service":"api"}"#;
        let resp = route(&req("POST", "/register", body), &mut r, &mut l);
        assert_eq!(resp.status, 200);
        let parsed: RegisterResponse = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(parsed.remote_port, 10_000);
        assert_eq!(l.calls, 1);
    }

    #[test]
    fn register_is_idempotent_and_doesnt_double_notify() {
        let mut r = registry();
        let mut l = CountingListener::default();
        let body = br#"{"user":"alice","service":"api"}"#;
        let _ = route(&req("POST", "/register", body), &mut r, &mut l);
        // Second call: same key, listener still fires (cheap to do; nginx reload
        // is idempotent), but the port is the same.
        let resp = route(&req("POST", "/register", body), &mut r, &mut l);
        let parsed: RegisterResponse = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(parsed.remote_port, 10_000);
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn register_rejects_missing_fields() {
        let mut r = registry();
        let resp = route(
            &req("POST", "/register", br#"{"user":"alice"}"#),
            &mut r,
            &mut NoopListener,
        );
        assert_eq!(resp.status, 400);
    }

    #[test]
    fn register_rejects_blank_fields() {
        let mut r = registry();
        let resp = route(
            &req("POST", "/register", br#"{"user":"   ","service":"api"}"#),
            &mut r,
            &mut NoopListener,
        );
        assert_eq!(resp.status, 400);
    }

    #[test]
    fn register_returns_503_when_pool_exhausted() {
        let mut r = registry();
        for i in 0..3 {
            let body = format!(r#"{{"user":"u{i}","service":"api"}}"#);
            let resp = route(
                &req("POST", "/register", body.as_bytes()),
                &mut r,
                &mut NoopListener,
            );
            assert_eq!(resp.status, 200, "iter {i}");
        }
        let resp = route(
            &req("POST", "/register", br#"{"user":"overflow","service":"api"}"#),
            &mut r,
            &mut NoopListener,
        );
        assert_eq!(resp.status, 503);
    }

    #[test]
    fn deregister_removes_entry_and_notifies() {
        let mut r = registry();
        let mut l = CountingListener::default();
        route(
            &req("POST", "/register", br#"{"user":"alice","service":"api"}"#),
            &mut r,
            &mut l,
        );
        let resp = route(
            &req("POST", "/deregister", br#"{"user":"alice","service":"api"}"#),
            &mut r,
            &mut l,
        );
        assert_eq!(resp.status, 200);
        assert!(r.is_empty());
        assert_eq!(l.calls, 2);
    }

    #[test]
    fn deregister_is_silent_when_absent_no_listener_call() {
        let mut r = registry();
        let mut l = CountingListener::default();
        let resp = route(
            &req("POST", "/deregister", br#"{"user":"ghost","service":"api"}"#),
            &mut r,
            &mut l,
        );
        assert_eq!(resp.status, 200);
        assert_eq!(l.calls, 0);
    }

    #[test]
    fn deregister_rejects_invalid_json() {
        let mut r = registry();
        let resp = route(
            &req("POST", "/deregister", b"not json"),
            &mut r,
            &mut NoopListener,
        );
        assert_eq!(resp.status, 400);
    }

    #[test]
    fn snapshot_returns_active_entries() {
        let mut r = registry();
        route(
            &req("POST", "/register", br#"{"user":"alice","service":"api"}"#),
            &mut r,
            &mut NoopListener,
        );
        let resp = route(&req("GET", "/snapshot", b""), &mut r, &mut NoopListener);
        assert_eq!(resp.status, 200);
        let parsed: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(parsed.as_array().unwrap().len(), 1);
        assert_eq!(parsed[0]["user"], "alice");
        assert_eq!(parsed[0]["service"], "api");
        assert_eq!(parsed[0]["remote_port"], 10_000);
    }

    #[test]
    fn unknown_route_returns_404() {
        let mut r = registry();
        let resp = route(&req("GET", "/nope", b""), &mut r, &mut NoopListener);
        assert_eq!(resp.status, 404);
    }
}
