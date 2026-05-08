use clap::{Args, Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Start running a service locally and route traffic to it from staging.
    Up(UpArgs),

    /// Stop a locally-running service and remove its routing entry.
    Down(DownArgs),

    /// List active local sessions for the current user.
    Status,

    /// Manage the shared bastion that backs the X-Ephemwork header.
    #[command(subcommand)]
    Bastion(BastionCommand),
}

#[derive(Args, Debug)]
pub struct UpArgs {
    /// Name of the service from ephemwork.toml.
    pub service: String,
}

#[derive(Args, Debug)]
pub struct DownArgs {
    /// Service to stop. If omitted, stops every active session for this user.
    pub service: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum BastionCommand {
    /// Provision the bastion EC2, security group, IAM role, and control plane.
    Init,
    /// Tear down the bastion and its supporting resources.
    Destroy,
    /// Show bastion status (instance ID, registered sessions).
    Status,
}

impl Cli {
    /// Parse from process args. Thin wrapper for symmetry with `try_parse_from`.
    pub fn parse_args() -> Self {
        Self::parse()
    }

    /// Used in tests to feed argv without touching `std::env::args`.
    pub fn try_parse_from_iter<I, T>(iter: I) -> Result<Self, clap::Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        Self::try_parse_from(iter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from_iter(args).expect("parse should succeed")
    }

    #[test]
    fn up_requires_a_service_argument() {
        let err = Cli::try_parse_from_iter(["ephemwork", "up"]).unwrap_err();
        assert!(
            err.to_string().to_lowercase().contains("service"),
            "expected a service-related error, got: {err}"
        );
    }

    #[test]
    fn up_parses_service_name() {
        let cli = parse(&["ephemwork", "up", "api"]);
        match cli.command {
            Command::Up(args) => assert_eq!(args.service, "api"),
            other => panic!("expected Up, got {other:?}"),
        }
    }

    #[test]
    fn down_with_no_service_is_optional() {
        let cli = parse(&["ephemwork", "down"]);
        match cli.command {
            Command::Down(args) => assert!(args.service.is_none()),
            other => panic!("expected Down, got {other:?}"),
        }
    }

    #[test]
    fn down_accepts_a_service_name() {
        let cli = parse(&["ephemwork", "down", "api"]);
        match cli.command {
            Command::Down(args) => assert_eq!(args.service.as_deref(), Some("api")),
            other => panic!("expected Down, got {other:?}"),
        }
    }

    #[test]
    fn status_takes_no_args() {
        let cli = parse(&["ephemwork", "status"]);
        assert!(matches!(cli.command, Command::Status));
    }

    #[test]
    fn bastion_init_parses() {
        let cli = parse(&["ephemwork", "bastion", "init"]);
        assert!(matches!(cli.command, Command::Bastion(BastionCommand::Init)));
    }

    #[test]
    fn bastion_destroy_parses() {
        let cli = parse(&["ephemwork", "bastion", "destroy"]);
        assert!(matches!(
            cli.command,
            Command::Bastion(BastionCommand::Destroy)
        ));
    }

    #[test]
    fn bastion_status_parses() {
        let cli = parse(&["ephemwork", "bastion", "status"]);
        assert!(matches!(
            cli.command,
            Command::Bastion(BastionCommand::Status)
        ));
    }

    #[test]
    fn bastion_requires_subcommand() {
        let err = Cli::try_parse_from_iter(["ephemwork", "bastion"]).unwrap_err();
        // clap returns an error rather than defaulting; just confirm it failed.
        assert!(err.to_string().len() > 0);
    }

    #[test]
    fn unknown_command_fails() {
        let err = Cli::try_parse_from_iter(["ephemwork", "frobnicate"]).unwrap_err();
        assert!(err.to_string().to_lowercase().contains("unrecognized")
            || err.to_string().to_lowercase().contains("invalid"));
    }
}
