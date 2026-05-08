use clap::Parser;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand)]
enum Commands {
    Up(UpArgs),
    Down(DownArgs),
    Status,
}

#[derive(clap::Args)]
struct UpArgs {
    service: String,
}

#[derive(clap::Args)]
struct DownArgs {
    service: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Up(args) => {
            println!("🚀 Starting {} locally...", args.service);
            // TODO: load config, run docker compose, setup tunnel
        }
        Commands::Down(args) => {
            println!("🛑 Stopping service...");
        }
        Commands::Status => {
            println!("📊 Current status");
        }
    }

    Ok(())
}
