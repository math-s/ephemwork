//! Wire types for the bastion control plane.
//!
//! These move to a shared `common/` crate in commit 8 when the bastion
//! server is introduced as a workspace member; they live here for now so
//! commit 7 can stand alone.

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
        // remote_port is required; absence must error rather than default.
        let res: Result<RegisterResponse, _> = serde_json::from_str("{}");
        assert!(res.is_err());
    }
}
