use ephemwork::aws_bastion_provisioner::AwsBastionProvisioner;
use ephemwork::bastion_provisioner::{
    render_bastion_status, run_destroy, run_init, run_status as run_bastion_status,
    security_group_plan, BastionContext, LaunchPlan, PlanLogger,
};
use ephemwork::cli::{
    BastionCommand, BastionDestroyArgs, BastionInitArgs, Cli, Command, DownArgs, UpArgs,
};
use ephemwork::commands::{
    down_service, render_status, status as run_status, up_service, UpRequest,
};
use ephemwork::config::{current_user, Config};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse_args();

    match cli.command {
        Command::Up(args) => up(args).await?,
        Command::Down(args) => down(args).await?,
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

fn ctx_from_config(cfg: &Config) -> BastionContext {
    BastionContext::new(cfg.tunnel.project_name.clone())
}

async fn up(args: UpArgs) -> anyhow::Result<()> {
    let cfg = Config::load()?;
    let user = current_user()?;
    let ctx = ctx_from_config(&cfg);
    let req = UpRequest::from_config(&cfg, &args.service, &user)?;
    let session = up_service(req, ctx).await?;

    println!();
    println!("✓ {} is live.", session.service);
    println!("  set this header on staging requests to route to your laptop:");
    println!();
    println!("    {}", session.header_line());
    println!();
    println!(
        "  pid={}  local:{}  bastion-port:{}",
        session.pid, session.local_port, session.remote_port
    );
    println!();
    println!("Press Ctrl-C to stop.");

    tokio::signal::ctrl_c().await?;
    println!();
    println!("Shutting down…");
    session.shutdown();
    Ok(())
}

async fn down(args: DownArgs) -> anyhow::Result<()> {
    let removed = down_service(args.service.clone()).await?;
    if removed.is_empty() {
        match args.service {
            Some(svc) => println!("no active session named {svc}"),
            None => println!("no active sessions"),
        }
    } else {
        for s in &removed {
            println!(
                "cleaned up {} (was bastion-port {})",
                s.service, s.remote_port
            );
        }
    }
    Ok(())
}

async fn bastion_init(args: BastionInitArgs) -> anyhow::Result<()> {
    let cfg = Config::load()?;
    let ctx = ctx_from_config(&cfg);
    let sg_plan = security_group_plan(&ctx, &args.alb_security_group_id)?;

    let build_launch_plan = |sg_id: &str| {
        LaunchPlan::from_config(
            &cfg.tunnel,
            &ctx,
            &args.ami_id,
            &args.subnet_id,
            sg_id,
            &args.bastion_binary_s3_uri,
        )
    };

    if !args.live {
        let mut logger = PlanLogger::new(ctx.clone());
        run_init(&mut logger, &ctx, &sg_plan, build_launch_plan)?;
        println!("Dry run (no AWS calls). Re-run with --live to provision.");
        for line in &logger.log {
            println!("  {line}");
        }
        return Ok(());
    }

    let mut provisioner =
        AwsBastionProvisioner::new(cfg.tunnel.region.clone(), ctx.clone()).await?;
    let outcome = run_init(&mut provisioner, &ctx, &sg_plan, build_launch_plan)?;
    let verb = if outcome.reused {
        "already provisioned"
    } else {
        "provisioned"
    };
    println!(
        "bastion {verb}: instance={} security_group={}",
        outcome.instance_id, outcome.security_group_id
    );
    if !outcome.reused {
        println!(
            "next: add the ALB listener rule documented in README.md, then \
             `ephemwork up <service>`."
        );
    }
    Ok(())
}

async fn bastion_destroy(args: BastionDestroyArgs) -> anyhow::Result<()> {
    let cfg = Config::load()?;
    let ctx = ctx_from_config(&cfg);

    if !args.live {
        let mut logger = PlanLogger::new(ctx.clone());
        // Show the destroy path with a synthetic existing instance.
        logger.pretend_existing = true;
        let outcome = run_destroy(&mut logger, &ctx)?;
        println!("Dry run (no AWS calls). Re-run with --live to delete.");
        for line in &logger.log {
            println!("  {line}");
        }
        if let Some(id) = &outcome.instance_id {
            println!("  (would terminate {id})");
        }
        return Ok(());
    }

    let mut provisioner =
        AwsBastionProvisioner::new(cfg.tunnel.region.clone(), ctx.clone()).await?;
    let outcome = run_destroy(&mut provisioner, &ctx)?;
    match outcome.instance_id {
        Some(id) => println!("terminated {id}; security group + IAM role removed."),
        None => println!("nothing to do (no bastion instance found)."),
    }
    Ok(())
}

async fn bastion_status() -> anyhow::Result<()> {
    let cfg = Config::load()?;
    let ctx = ctx_from_config(&cfg);
    let mut provisioner =
        AwsBastionProvisioner::new(cfg.tunnel.region.clone(), ctx.clone()).await?;
    let status = run_bastion_status(&mut provisioner, &ctx)?;
    println!("{}", render_bastion_status(&status, &ctx));
    Ok(())
}
