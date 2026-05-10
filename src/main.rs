use ephemwork::aws_bastion_provisioner::{verify_vpc_match, AwsBastionProvisioner};
use ephemwork::bastion_provisioner::{
    render_bastion_status, run_destroy, run_init, run_status as run_bastion_status,
    security_group_plan, BastionContext, BastionProvisioner, LaunchPlan, PlanLogger,
};
use ephemwork::cli::{
    BastionCommand, BastionDestroyArgs, BastionInitArgs, BastionRedeployArgs, Cli, Command,
    DownArgs, UpArgs,
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
            BastionCommand::Redeploy(args) => bastion_redeploy(args).await?,
            BastionCommand::Doctor => bastion_doctor().await?,
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
    match (session.local_port, session.remote_port) {
        (Some(local), Some(remote)) => {
            println!("  set this header on staging requests to route to your laptop:");
            println!();
            println!("    {}", session.header_line());
            println!();
            println!(
                "  pid={}  local:{}  bastion-port:{}",
                session.pid, local, remote
            );
        }
        _ => {
            println!("  worker mode: no inbound HTTP routing.");
            println!("  pid={}", session.pid);
        }
    }
    println!();
    println!("Press Ctrl-C to stop.");

    // Race Ctrl-C with the SSH tunnel's dead-session flag. If the reverse
    // forward dies (network blip, bastion restart, suspend/resume), keeping
    // ephemwork running just means the bastion's nginx 502s every tagged
    // request — surface the death immediately so the developer can re-run.
    //
    // SIGTERM gets the same handling as Ctrl-C: pkill / launchd-style stop
    // / shell-script cleanup all use SIGTERM by default, and without this
    // arm the process gets SIGKILL'd before Drop runs and uvicorn etc.
    // descendants survive (defeating the process-group cleanup).
    let mut sigterm = tokio::signal::unix::signal(
        tokio::signal::unix::SignalKind::terminate(),
    )?;
    let exit_reason = tokio::select! {
        result = tokio::signal::ctrl_c() => {
            result?;
            "ctrl-c"
        }
        _ = sigterm.recv() => {
            "sigterm"
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

async fn bastion_redeploy(args: BastionRedeployArgs) -> anyhow::Result<()> {
    let cfg = Config::load()?;
    let ctx = ctx_from_config(&cfg);

    // 1. Locate the running bastion (we need its instance ID for the
    //    SSM Run Command). Errors clearly when none is provisioned.
    let mut provisioner =
        AwsBastionProvisioner::new(cfg.tunnel.region.clone(), ctx.clone()).await?;
    let bastion = provisioner
        .find_instance_by_name(&ctx.instance_name())?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no bastion found for project {:?}; run `ephemwork bastion init --live` first",
                ctx.project_name
            )
        })?;
    println!("→ targeting bastion {}", bastion.instance_id);

    // 2. Build the binary.
    if !args.skip_build {
        println!("→ cargo zigbuild --release --target aarch64-unknown-linux-musl");
        let status = std::process::Command::new("cargo")
            .args([
                "zigbuild",
                "--release",
                "--target",
                "aarch64-unknown-linux-musl",
                "-p",
                "ephemwork-bastion-server",
            ])
            .status()
            .map_err(|e| anyhow::anyhow!("spawning cargo zigbuild: {e}"))?;
        if !status.success() {
            return Err(anyhow::anyhow!("cargo zigbuild failed (status {status:?})"));
        }
    } else {
        println!("→ --skip-build: not building the binary");
    }

    let binary_path = "target/aarch64-unknown-linux-musl/release/ephemwork-bastion-server";
    if !std::path::Path::new(binary_path).exists() {
        return Err(anyhow::anyhow!(
            "binary not found at {binary_path}. Either run without --skip-build, or build it manually first."
        ));
    }

    // 3. Upload to S3.
    println!("→ aws s3 cp {binary_path} {}", args.bastion_binary_s3_uri);
    let status = std::process::Command::new("aws")
        .args(["s3", "cp", binary_path, &args.bastion_binary_s3_uri])
        .status()
        .map_err(|e| anyhow::anyhow!("spawning aws s3 cp: {e}"))?;
    if !status.success() {
        return Err(anyhow::anyhow!("aws s3 cp failed (status {status:?})"));
    }

    // 4. SSM Run Command on the bastion: re-pull, swap, restart.
    let script = ephemwork::bastion_provisioner::redeploy_script(&args.bastion_binary_s3_uri);
    println!("→ aws ssm send-command (swap binary + restart systemd unit)");
    run_ssm_redeploy(&cfg.tunnel.region, &bastion.instance_id, &script)?;

    println!();
    println!("✓ bastion-server redeployed on {}", bastion.instance_id);
    Ok(())
}

fn run_ssm_redeploy(region: &str, instance_id: &str, script: &str) -> anyhow::Result<()> {
    use std::process::Command;
    use std::time::Duration;

    let parameters = format!(
        "commands={}",
        serde_json::to_string(&vec![script.to_string()])?
    );
    let send = Command::new("aws")
        .args([
            "ssm",
            "send-command",
            "--region",
            region,
            "--instance-ids",
            instance_id,
            "--document-name",
            "AWS-RunShellScript",
            "--parameters",
            &parameters,
            "--query",
            "Command.CommandId",
            "--output",
            "text",
        ])
        .output()
        .map_err(|e| anyhow::anyhow!("spawning aws ssm send-command: {e}"))?;
    if !send.status.success() {
        return Err(anyhow::anyhow!(
            "aws ssm send-command failed: {}",
            String::from_utf8_lossy(&send.stderr).trim()
        ));
    }
    let cmd_id = String::from_utf8_lossy(&send.stdout).trim().to_string();
    if cmd_id.is_empty() {
        return Err(anyhow::anyhow!("SSM send-command returned empty command id"));
    }
    println!("  SSM command id: {cmd_id}");

    // Poll until terminal status. Bounded so a hung command doesn't
    // wedge the whole flow.
    let deadline = std::time::Instant::now() + Duration::from_secs(180);
    loop {
        std::thread::sleep(Duration::from_secs(5));
        let status_out = Command::new("aws")
            .args([
                "ssm",
                "get-command-invocation",
                "--region",
                region,
                "--command-id",
                &cmd_id,
                "--instance-id",
                instance_id,
                "--query",
                "Status",
                "--output",
                "text",
            ])
            .output();
        let status = match status_out {
            Ok(o) if o.status.success() => {
                String::from_utf8_lossy(&o.stdout).trim().to_string()
            }
            _ => {
                if std::time::Instant::now() >= deadline {
                    return Err(anyhow::anyhow!("SSM command status poll timed out"));
                }
                continue;
            }
        };
        match status.as_str() {
            "Success" => return Ok(()),
            "Failed" | "Cancelled" | "TimedOut" => {
                let body = Command::new("aws")
                    .args([
                        "ssm",
                        "get-command-invocation",
                        "--region",
                        region,
                        "--command-id",
                        &cmd_id,
                        "--instance-id",
                        instance_id,
                        "--query",
                        "[StandardOutputContent,StandardErrorContent]",
                        "--output",
                        "text",
                    ])
                    .output()
                    .ok()
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                    .unwrap_or_default();
                return Err(anyhow::anyhow!(
                    "SSM command ended with {status}:\n{body}"
                ));
            }
            _ => {
                if std::time::Instant::now() >= deadline {
                    return Err(anyhow::anyhow!(
                        "SSM command stuck in status {status} after 3 min"
                    ));
                }
            }
        }
    }
}

async fn bastion_doctor() -> anyhow::Result<()> {
    let cfg = Config::load()?;
    let ctx = ctx_from_config(&cfg);
    let mut provisioner =
        AwsBastionProvisioner::new(cfg.tunnel.region.clone(), ctx.clone()).await?;

    let mut issues: Vec<String> = Vec::new();
    println!("ephemwork bastion doctor for project {:?}", ctx.project_name);
    println!();

    // 1. Instance lookup.
    let instance = provisioner.find_instance_by_name(&ctx.instance_name())?;
    let instance = match instance {
        Some(i) => {
            println!("✓ instance: {} ({})", i.instance_id, i.state);
            if let Some(ip) = &i.private_ip {
                println!("    private_ip: {ip}");
            }
            if let Some(sg) = &i.security_group_id {
                println!("    security_group: {sg}");
            }
            if i.state != "running" {
                issues.push(format!(
                    "instance state is {:?} — expected running",
                    i.state
                ));
            }
            i
        }
        None => {
            println!("✗ no instance tagged Name={}", ctx.instance_name());
            issues.push("bastion not provisioned".into());
            print_issues(&issues);
            return Ok(());
        }
    };

    // 2. SSM agent status.
    println!();
    match provisioner.ssm_agent_status(&instance.instance_id).await {
        Ok(Some(info)) if info.ping_status == "Online" => {
            println!(
                "✓ SSM agent: Online (v{}, last ping {})",
                info.agent_version.unwrap_or_else(|| "?".into()),
                info.last_ping.unwrap_or_else(|| "?".into()),
            );
        }
        Ok(Some(info)) => {
            println!("⚠  SSM agent: {}", info.ping_status);
            issues.push(format!("SSM agent ping status is {}", info.ping_status));
        }
        Ok(None) => {
            println!("✗ SSM agent: NOT registered");
            issues.push(
                "SSM agent never registered with Systems Manager. Most likely cause: \
                 VPC endpoint SG doesn't allow bastion → :443 (see check below). Other \
                 causes: missing IAM role, missing internet egress."
                    .into(),
            );
        }
        Err(e) => {
            println!("⚠  SSM agent check failed: {e}");
            issues.push(format!("SSM agent check failed: {e}"));
        }
    }

    // 3. VPC endpoint SG ingress.
    println!();
    if let Some(vpc_id) = cfg.tunnel.expected_vpc_id.as_deref() {
        let bastion_sg = instance
            .security_group_id
            .as_deref()
            .unwrap_or("(unknown)");
        match provisioner
            .missing_vpc_endpoint_ingress(vpc_id, bastion_sg)
            .await
        {
            Ok(missing) if missing.is_empty() => {
                println!("✓ VPC endpoint SGs: all allow bastion → :443");
            }
            Ok(missing) => {
                println!(
                    "⚠  {} VPC interface endpoint SG(s) don't allow inbound from bastion:",
                    missing.len()
                );
                let profile = std::env::var("AWS_PROFILE").ok();
                for m in &missing {
                    println!("    - {} (sg {})", m.endpoint_service, m.endpoint_sg_id);
                    println!(
                        "      fix: {}",
                        m.fix_command(bastion_sg, profile.as_deref())
                            .replace('\n', "\n            ")
                    );
                }
                issues.push(format!(
                    "{} VPC endpoint SG(s) need ingress from bastion",
                    missing.len()
                ));
            }
            Err(e) => {
                println!("⚠  VPC endpoint SG check failed: {e}");
                issues.push(format!("VPC endpoint check failed: {e}"));
            }
        }
    } else {
        println!("(skipping VPC endpoint check — set tunnel.expected_vpc_id)");
    }

    print_issues(&issues);
    if !issues.is_empty() {
        std::process::exit(1);
    }
    Ok(())
}

fn print_issues(issues: &[String]) {
    println!();
    if issues.is_empty() {
        println!("✓ bastion is healthy");
    } else {
        println!("✗ {} issue(s):", issues.len());
        for i in issues {
            println!("  - {i}");
        }
    }
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
