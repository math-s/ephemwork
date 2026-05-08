pub mod bastion_client;
pub mod cli;
pub mod commands;
pub mod config;
pub mod runner;
pub mod ssm;
pub mod state;
pub mod tunnel;

// Re-export the shared protocol types for backwards compatibility within the
// crate; new code should import from `ephemwork_common` directly.
pub mod bastion_protocol {
    pub use ephemwork_common::{
        DeregisterRequest, ErrorResponse, RegisterRequest, RegisterResponse,
    };
}
