//! Wire types shared between the laptop CLI and the bastion control plane.
//!
//! Lives in its own crate so that changes to the bastion server can't compile
//! against incompatible request/response shapes.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegisterRequest {
    pub user: String,
    pub service: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegisterResponse {
    /// Port allocated on the bastion that the laptop should reverse-forward to.
    pub remote_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeregisterRequest {
    pub user: String,
    pub service: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ErrorResponse {
    pub error: String,
}

/// Header that staging traffic carries to be routed to a developer's tunnel.
pub const ROUTING_HEADER: &str = "X-Ephemwork";

/// Build the header value for a (user, service) pair. User is lower-cased so
/// the bastion can match deterministically; service casing is preserved.
pub fn routing_header_value(user: &str, service: &str) -> String {
    format!("{}:{}", user.trim().to_lowercase(), service.trim())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_request_round_trips() {
        let r = RegisterRequest {
            user: "matheus".into(),
            service: "api".into(),
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: RegisterRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn register_response_round_trips() {
        let r = RegisterResponse { remote_port: 9001 };
        let json = serde_json::to_string(&r).unwrap();
        let back: RegisterResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn deregister_request_round_trips() {
        let r = DeregisterRequest {
            user: "matheus".into(),
            service: "api".into(),
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: DeregisterRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn register_response_rejects_missing_field() {
        let res: Result<RegisterResponse, _> = serde_json::from_str("{}");
        assert!(res.is_err());
    }

    #[test]
    fn header_value_lowercases_user_only() {
        assert_eq!(routing_header_value("Matheus", "API-v2"), "matheus:API-v2");
    }

    #[test]
    fn header_value_trims_whitespace() {
        assert_eq!(routing_header_value("  alice ", "  api "), "alice:api");
    }
}
