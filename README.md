# ephemwork

A Rust CLI for selective local development in AWS-native staging environments.

Run **only** the service you're changing locally; everything else stays in
staging. Requests carrying `X-Ephemwork: <user>:<service>` are routed from the
ALB to the developer's laptop instead of the staging task.

## How it works

```
laptop:8000 ──reverse SSH──┐
                           │
                           ▼
                    bastion (EC2 in staging VPC)
                    ├─ nginx (header → port map)
                    └─ ephemwork-bastion-server (control plane)
                           ▲
                           │ ALB listener rule:
                           │ "X-Ephemwork header present"
                           │
                    staging ALB
```

- The laptop opens a reverse SSH tunnel to the bastion **through SSM
  Session Manager port forwarding** — the bastion's port 22 stays closed to
  the internet; access is gated by the developer's IAM identity.
- The bastion's nginx maps the `X-Ephemwork` header value to a per-tunnel
  port and proxies the request back through the open SSH channel.
- A small Rust control plane on the bastion (`ephemwork-bastion-server`)
  allocates ports, persists active sessions, and reloads nginx after every
  change.
- Requests **without** the header take the normal path through the existing
  staging task — production users are never affected by developer activity.

## Workspace layout

| Crate | Purpose |
|---|---|
| `ephemwork` (root) | The developer-facing CLI: `up` / `down` / `status` / `bastion {init, destroy, status}` |
| `common` | Wire types shared between laptop and bastion (`RegisterRequest`, `RegisterResponse`, etc.) |
| `bastion-server` | The control plane that runs on the bastion EC2: HTTP API + nginx reloader |

## Configuration

`ephemwork.toml` at your repo root:

```toml
[tunnel]
type = "ec2"
region = "us-east-1"
instance_type = "t4g.nano"

[service.api]
port = 8000
build_command = "uv sync"
run_command = "uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload"
health_check_path = "/health"

[service.front-end]
port = 5173
run_command = "npm run dev"
```

The user identifier in the header defaults to the local part of
`git config user.email`, and can be overridden with `EPHEMWORK_USER`.

## Setup

### 1. Build the bastion-server for arm64

The bastion runs on a `t4g.nano` (arm64), so cross-compile from your laptop:

```bash
rustup target add aarch64-unknown-linux-musl
cargo build --release --target aarch64-unknown-linux-musl -p ephemwork-bastion-server
aws s3 cp \
  target/aarch64-unknown-linux-musl/release/ephemwork-bastion-server \
  s3://your-ops-bucket/ephemwork-bastion-server
```

### 2. Provision the bastion

Always do a dry run first — it prints the plan without calling AWS:

```bash
ephemwork bastion init \
  --ami-id ami-0xxx                      \  # AL2023 arm64 with SSM agent
  --subnet-id subnet-xxx                 \  # private subnet in staging VPC
  --alb-security-group-id sg-xxx         \  # so bastion only accepts from ALB
  --bastion-binary-s3-uri s3://your-ops-bucket/ephemwork-bastion-server
```

Add `--live` once you've reviewed the plan.

> **Status:** the live AWS path is wired to error with a clear pointer until
> the `BastionProvisioner` trait gets an `aws-sdk-ec2`/`aws-sdk-iam` impl.
> The dry-run path, plan builders, and orchestration logic are fully
> unit-tested.

### 3. Add the ALB listener rules

For an AWS CDK (Python) consumer, drop this into your existing
`ApplicationLoadBalancer`'s listener. **Read every comment** — three of
the four caveats below cost real PRs to fix in production-adjacent infra
during MotoCred adoption.

```python
from aws_cdk import (
    aws_ec2 as ec2,
    aws_elasticloadbalancingv2 as elbv2,
    aws_elasticloadbalancingv2_targets as elbv2_targets,
)

# 1. Target group: an IP target on the bastion's private IP, port 80.
#
# Caveat A — `availability_zone`: do NOT pass `availability_zone="all"`.
# That option is ONLY valid for IPs *outside* the VPC (on-prem reached via
# Direct Connect / VPN). For an in-VPC IP like the bastion's, ELB infers
# the AZ from the route table; passing 'all' fails CFN with
# `The IP address '...' is within the VPC, and cannot have its
# Availability Zone overridden to 'all' from 'us-east-1a'`.
bastion_target_group = elbv2.ApplicationTargetGroup(
    self,
    "EphemworkBastionTG",
    vpc=vpc,
    port=80,
    protocol=elbv2.ApplicationProtocol.HTTP,
    target_type=elbv2.TargetType.IP,
    targets=[elbv2_targets.IpTarget(bastion_private_ip, port=80)],
    health_check=elbv2.HealthCheck(
        path="/ephemwork-health",
        healthy_http_codes="200",
        interval=Duration.seconds(30),
        timeout=Duration.seconds(5),
    ),
)

# 2. The main listener rule: route requests carrying X-Ephemwork to the
#    bastion target group.
elbv2.ApplicationListenerRule(
    self,
    "EphemworkRoute",
    listener=https_listener,
    priority=10,                         # higher than the default catch-all
    conditions=[
        elbv2.ListenerCondition.http_header(
            "X-Ephemwork",
            ["?*"],                      # any non-empty value
        ),
    ],
    action=elbv2.ListenerAction.forward([bastion_target_group]),
)

# 3. CORS preflight routing. Browsers strip custom headers from OPTIONS
#    preflights; instead they list them in `Access-Control-Request-Headers`.
#    Without this rule the preflight goes to your normal backend (which
#    may not list X-Ephemwork in its CORS allowlist), the browser blocks,
#    and the actual request never fires. With this rule, preflights for
#    X-Ephemwork-tagged requests also land on the bastion → laptop, so any
#    CORS changes you make locally take effect immediately.
elbv2.ApplicationListenerRule(
    self,
    "EphemworkCorsPreflightRoute",
    listener=https_listener,
    priority=11,
    conditions=[
        elbv2.ListenerCondition.http_header(
            "Access-Control-Request-Headers",
            ["*x-ephemwork*", "*X-Ephemwork*"],
        ),
    ],
    action=elbv2.ListenerAction.forward([bastion_target_group]),
)

# 4. ALB SG egress to the bastion's SG.
#
# Caveat B — the `ApplicationLoadBalancedFargateService` pattern only
# opens egress on its ALB SG to its own backend tasks. For a raw IP
# target like the bastion's, CDK can't infer the destination SG, so no
# egress rule is added. Without this, the target health check times out
# and the ALB never forwards. The bastion's SG ID is what
# `ephemwork bastion init --live` printed (or fetch from CFN).
bastion_sg = ec2.SecurityGroup.from_security_group_id(
    self,
    "EphemworkBastionSG",
    bastion_security_group_id,
    mutable=False,                       # owned by the ephemwork CLI
)
service.load_balancer.connections.allow_to(
    bastion_sg,
    ec2.Port.tcp(80),
    "ALB to ephemwork bastion (X-Ephemwork header)",
)
```

Requests **without** `X-Ephemwork` fall through to your existing rules
unchanged. Production stays untouched as long as you gate the entire
block on a per-environment config flag (e.g. only set `bastion_private_ip`
for staging).

### 3a. Allow `X-Ephemwork` in your back-end's CORS allowlist

Your back-end's CORS middleware must include `X-Ephemwork` in its
`allow_headers` list, otherwise the browser preflight from the staging FE
returns `400 Disallowed CORS headers` even when the listener rules above
are correct. For FastAPI:

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=[...],
    allow_methods=[...],
    allow_headers=[
        "Authorization",
        "Content-Type",
        # ... your existing headers ...
        "X-Ephemwork",                   # <-- add this
    ],
)
```

This change is safe for production: the FE only sets `X-Ephemwork` in
staging (gate the widget on `VITE_SENTRY_ENVIRONMENT === "staging"` or
similar), so prod traffic never carries the header even when the
allow_headers list contains it.

### 4. Set the header in the staging UI

Two reasonable options:

- A browser extension that injects `X-Ephemwork: <you>:<service>` for the
  staging origin only.
- A staging-only middleware that reads `?ephem=<user>:<service>` from the
  URL and re-emits it as a cookie + header on subsequent requests. Lower
  friction for one-off testing; do **not** ship this to production.

## Daily workflow

```bash
ephemwork up api          # spawn local service, open tunnel, register with bastion
# ... edit code, hot reload picks up changes ...
ephemwork status          # show your active sessions
ephemwork down api        # stop the local service and tear down the tunnel
ephemwork down            # stop everything for the current user
```

### Editing the env file? Restart the whole `ephemwork up`

`ephemwork up` exports your env file once when it spawns the service, then
your service's own watcher (e.g. `uvicorn --reload`) re-reads source files
on save. **Watchers don't re-source env files.** If you edit
`.env.staging` (or whatever your `run_command` sources) you need to:

1. Ctrl-C the running `ephemwork up` (sends SIGINT, deregisters with
   bastion, kills the local service).
2. Re-run `ephemwork up <service>`.

Just saving the file and waiting won't propagate the change — your
service is still living with the old env.

## Threat model

- **No public SSH on the bastion.** Port 22 is bound to the SG only; the
  developer reaches it via SSM Session Manager port forwarding, gated by
  IAM permissions.
- **Header presence ≠ trust.** The ALB rule routes any traffic with the
  header to the bastion, but unknown header values get a 404 from nginx.
  This means a curious user can probe header values, not impersonate a
  service. Treat staging as an internal environment behind your existing
  authentication.
- **No production exposure.** The header is only honored on the staging
  ALB. Production should not have the listener rule installed.

## Status

Phase 1 + 2 of the implementation are complete:

| Area | Status |
|---|---|
| Config + identity resolution | done, unit tested |
| Local session state (`~/.ephemwork/state.json`) | done, unit tested |
| SSM port-forward helper | done, unit tested |
| Reverse SSH tunnel (config, lifecycle, byte pump) | done; live ssh2 path validated manually |
| Process runner + health check | done, unit tested |
| Bastion control plane (HTTP, registry, persistence) | done, unit + integration tested |
| nginx config rendering + reload | done, unit tested |
| Bastion EC2 provisioner | plan + dry-run done; **live AWS impl pending** |
| Bastion destroy / status | plan + dry-run done; **live AWS impl pending** |

Workspace test count: **153** (99 ephemwork + 48 bastion-server + 6 common).
Run `cargo test --workspace`.

## Local development of ephemwork itself

```bash
cargo build --workspace
cargo test --workspace
```

The shared bastion model (one EC2 per team) and SSM-only access were locked
in during the design conversation — see `git log` if you need the rationale.
