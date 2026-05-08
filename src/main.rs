use ephemwork::cli::{BastionCommand, Cli, Command};
use ephemwork::commands::{render_status, status as run_status};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse_args();

    match cli.command {
        Command::Up(args) => {
            // Full up flow (SSM forward + SSH reverse tunnel + process + bastion
            // registration) is wired against a live bastion in Phase 1's manual
            // smoke test; commit 8 lights up the bastion server itself.
            println!(
                "up: {} (Phase 1 wiring - run smoke test against a live bastion)",
                args.service
            );
        }
        Command::Down(args) => match args.service {
            Some(service) => println!("down: {service} (Phase 1 wiring)"),
            None => println!("down: all services (Phase 1 wiring)"),
        },
        Command::Status => {
            let out = run_status()?;
            println!("{}", render_status(&out));
        }
        Command::Bastion(cmd) => match cmd {
            BastionCommand::Init => println!("bastion init (lands in commit 10)"),
            BastionCommand::Destroy => println!("bastion destroy (lands in commit 11)"),
            BastionCommand::Status => println!("bastion status (lands in commit 11)"),
        },
    }

    Ok(())
}
