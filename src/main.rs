use ephemwork::cli::{BastionCommand, Cli, Command};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse_args();

    match cli.command {
        Command::Up(args) => {
            println!("up: {} (not yet implemented)", args.service);
        }
        Command::Down(args) => match args.service {
            Some(service) => println!("down: {service} (not yet implemented)"),
            None => println!("down: all services for current user (not yet implemented)"),
        },
        Command::Status => {
            println!("status: (not yet implemented)");
        }
        Command::Bastion(cmd) => match cmd {
            BastionCommand::Init => println!("bastion init (not yet implemented)"),
            BastionCommand::Destroy => println!("bastion destroy (not yet implemented)"),
            BastionCommand::Status => println!("bastion status (not yet implemented)"),
        },
    }

    Ok(())
}
