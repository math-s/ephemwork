use ephemwork::aws_bastion_provisioner::AwsBastionProvisioner;
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
            BastionCommand::Init(args) => bastion_init(args).await?,
            BastionCommand::Destroy(args) => bastion_destroy(args).await?,
            BastionCommand::Status => bastion_status().await?,
        },
    }

    Ok(())
}

async fn bastion_init(args: BastionInitArgs) -> anyhow::Result<()> {
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

    let mut provisioner = AwsBastionProvisioner::new(cfg.tunnel.region.clone()).await?;
    let outcome = run_init(&mut provisioner, &sg_plan, |sg_id| {
        LaunchPlan::from_config(
            &cfg.tunnel,
            &args.ami_id,
            &args.subnet_id,
            sg_id,
            &args.bastion_binary_s3_uri,
        )
    })?;
    println!(
        "bastion provisioned: instance={} security_group={}",
        outcome.instance_id, outcome.security_group_id
    );
    println!("next: add the ALB listener rule documented in README.md, then `ephemwork up <service>`.");
    Ok(())
}

async fn bastion_destroy(args: BastionDestroyArgs) -> anyhow::Result<()> {
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

    let cfg = Config::load()?;
    let mut provisioner = AwsBastionProvisioner::new(cfg.tunnel.region.clone()).await?;
    let outcome = run_destroy(&mut provisioner)?;
    match outcome.instance_id {
        Some(id) => println!("terminated {id}; security group + IAM role removed."),
        None => println!("nothing to do (no bastion instance found)."),
    }
    Ok(())
}

async fn bastion_status() -> anyhow::Result<()> {
    let cfg = Config::load()?;
    let mut provisioner = AwsBastionProvisioner::new(cfg.tunnel.region.clone()).await?;
    let status = run_bastion_status(&mut provisioner)?;
    println!("{}", render_bastion_status(&status));
    Ok(())
}
