use ephemwork::bastion_provisioner::{
    render_bastion_status, run_destroy, run_init, run_status as run_bastion_status,
    security_group_plan, LaunchPlan, PlanLogger,
};
use ephemwork::cli::{BastionCommand, BastionDestroyArgs, BastionInitArgs, Cli, Command};
use ephemwork::commands::{render_status, status as run_status};
use ephemwork::config::Config;

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
            BastionCommand::Init(args) => bastion_init(args)?,
            BastionCommand::Destroy(args) => bastion_destroy(args)?,
            BastionCommand::Status => bastion_status()?,
        },
    }

    Ok(())
}

fn bastion_init(args: BastionInitArgs) -> anyhow::Result<()> {
    let cfg = Config::load()?;
    let sg_plan = security_group_plan(&args.alb_security_group_id)?;

    if !args.live {
        let mut logger = PlanLogger::new();
        run_init(&mut logger, &sg_plan, |sg_id| {
            LaunchPlan::from_config(
                &cfg.tunnel,
                &args.ami_id,
                &args.subnet_id,
                sg_id,
                &args.bastion_binary_s3_uri,
            )
        })?;
        println!("Dry run (no AWS calls). Re-run with --live to provision.");
        for line in &logger.log {
            println!("  {line}");
        }
        return Ok(());
    }

    Err(anyhow::anyhow!(
        "live AWS provisioning is not yet implemented; the BastionProvisioner trait \
         in src/bastion_provisioner.rs defines the four calls needed against \
         aws-sdk-ec2 / aws-sdk-iam. Until that lands, run without --live to view \
         the plan."
    ))
}

fn bastion_destroy(args: BastionDestroyArgs) -> anyhow::Result<()> {
    if !args.live {
        let mut logger = PlanLogger::new();
        let outcome = run_destroy(&mut logger)?;
        println!("Dry run (no AWS calls). Re-run with --live to delete.");
        for line in &logger.log {
            println!("  {line}");
        }
        if let Some(id) = &outcome.instance_id {
            println!("  (would terminate {id})");
        }
        return Ok(());
    }
    Err(anyhow::anyhow!(
        "live AWS teardown is not yet implemented; provide a BastionProvisioner \
         impl wired against aws-sdk-ec2 / aws-sdk-iam. Without --live, the dry \
         run prints the plan."
    ))
}

fn bastion_status() -> anyhow::Result<()> {
    let mut logger = PlanLogger::new();
    let status = run_bastion_status(&mut logger)?;
    println!("{}", render_bastion_status(&status));
    println!("(dry run; live AWS lookup pending --live wiring of BastionProvisioner)");
    Ok(())
}
