use ephemwork::aws_bastion_provisioner::{verify_vpc_match, AwsBastionProvisioner};
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

    // Race Ctrl-C with the SSH tunnel's dead-session flag. If the reverse
    // forward dies (network blip, bastion restart, suspend/resume), keeping
    // ephemwork running just means the bastion's nginx 502s every tagged
    // request — surface the death immediately so the developer can re-run.
    let exit_reason = tokio::select! {
        result = tokio::signal::ctrl_c() => {
            result?;
            "ctrl-c"
        }
        _ = wait_for_tunnel_death(&session) => {
            "tunnel-died"
        }
    };

    println!();
    match exit_reason {
        "tunnel-died" => println!(
            "✗ SSH reverse tunnel to the bastion died (network drop / bastion \
             restart / suspend). Re-run `ephemwork up {}` to reconnect.",
            session.service
        ),
        _ => println!("Shutting down…"),
    }
    session.shutdown();
    if exit_reason == "tunnel-died" {
        std::process::exit(2);
    }
    Ok(())
}

async fn wait_for_tunnel_death(session: &ephemwork::commands::ActiveSession) {
    // Poll once a second; this is a long-lived watchdog so the cost is
    // negligible. We don't try to hook into ssh2 callbacks because the
    // worker thread is sync and re-entry from tokio is awkward.
    loop {
        if session.tunnel_is_dead() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
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

    // Read the SSH public key once so the closure below can borrow it.
    let ssh_key = match &args.ssh_public_key {
        Some(path) => Some(
            std::fs::read_to_string(path)
                .map_err(|e| anyhow::anyhow!("reading {}: {e}", path.display()))?,
        ),
        None => None,
    };

    let build_launch_plan = |sg_id: &str| {
        LaunchPlan::from_config(
            &cfg.tunnel,
            &ctx,
            &args.ami_id,
            &args.subnet_id,
            sg_id,
            &args.bastion_binary_s3_uri,
            ssh_key.as_deref(),
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

    // Prod-safety guard: if the toml pins expected_vpc_id, abort before
    // creating anything when the supplied subnet is in a different VPC.
    if let Some(expected_vpc) = cfg.tunnel.expected_vpc_id.as_deref() {
        let actual_vpc = provisioner.vpc_id_for_subnet(&args.subnet_id).await?;
        verify_vpc_match(&args.subnet_id, &actual_vpc, expected_vpc)?;
    }

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

    // Post-flight: detect VPC interface endpoints whose SGs don't allow
    // the bastion → :443. The bastion's SSM agent silently fails to
    // register against those endpoints (DNS resolves to private IPs that
    // the bastion can't reach), and `aws ssm describe-instance-information`
    // never lists the instance. Don't auto-mutate shared infra; print the
    // exact authorize-security-group-ingress commands and let the operator
    // run them.
    if let Some(vpc_id) = cfg.tunnel.expected_vpc_id.as_deref() {
        match provisioner
            .missing_vpc_endpoint_ingress(vpc_id, &outcome.security_group_id)
            .await
        {
            Ok(missing) if missing.is_empty() => {
                println!("VPC endpoint SGs already allow the bastion. ✓");
            }
            Ok(missing) => {
                println!();
                println!(
                    "⚠  {} VPC interface endpoint security group(s) don't allow inbound \
                     :443 from the bastion's SG. The bastion's SSM agent will fail to \
                     register until you add these rules:",
                    missing.len()
                );
                println!();
                let profile = std::env::var("AWS_PROFILE").ok();
                for m in &missing {
                    println!("  # {}", m.endpoint_service);
                    println!(
                        "  {}",
                        m.fix_command(&outcome.security_group_id, profile.as_deref())
                            .replace('\n', "\n  ")
                    );
                    println!();
                }
            }
            Err(e) => {
                tracing::warn!(?e, "VPC endpoint SG check failed; skipping");
            }
        }
    } else {
        println!(
            "(skipping VPC endpoint SG check; set tunnel.expected_vpc_id in \
             ephemwork.toml to enable.)"
        );
    }

    if !outcome.reused {
        println!();
        println!(
            "next: add the ALB listener rules documented in README.md, then \
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
