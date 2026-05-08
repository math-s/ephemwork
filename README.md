# ephemwork

**Ephemeral Work: Selective local development for cloud-native apps**

A Rust CLI tool that lets you run *only* the services you're changing locally (e.g. one AWS Lambda), while everything else stays in your staging/production environment.

Requests from the frontend are smart-routed via a simple HTTP header — no need to deploy or mock the entire stack.

## The Problem
In cloud-native / serverless setups (Lambda, containers, etc.), local development is painful:
- Full local stack = heavy and out-of-sync
- Full cloud deploy = slow feedback loop

**ephemwork** solves this with **ephemeral overrides**.

## How It Works (User Flow)
1. You change one service (e.g. `my-lambda`)
2. Run: `ephemwork up my-lambda`
   - Starts the service locally
   - Creates a secure tunnel (public URL)
3. In your frontend (or any client), add a header to all requests:
   ```http
   X-Ephemwork: math-s:my-lambda
   ```
4. Your staging environment sees the header and routes *only* that request to your local tunnel.
5. All other traffic hits the real staging services.

Perfect for microservices / serverless where you're iterating on one piece at a time.

## High-Level Architecture
- **Local CLI** (`ephemwork` Rust binary)
- **Service Runner**: Executes your code locally (Lambda runtime emulation, etc.)
- **Tunnel Manager**: Securely exposes your local service (ngrok / cloudflared / custom)
- **Cloud Router** (deployed in staging): Header-based proxy/middleware that forwards matching requests to your tunnel

## MVP Scope (Phase 1)
- AWS Lambda support (HTTP-triggered, Rust/Node runtimes first)
- `up` / `down` / `status` CLI commands
- ngrok-based tunneling
- Basic header routing spec
- Configuration via TOML

Future phases: multiple services at once, more cloud providers, Kubernetes, containers, etc.

## Tech Stack
- **Language**: Rust
- **CLI**: clap
- **Async**: tokio + axum/hyper
- **Config**: serde + toml
- **AWS integration**: aws-lambda-rust-runtime (or custom HTTP wrapper)
- **Tunneling**: ngrok crate or subprocess

## Proposed Repository Structure
```bash
ephemwork/
├── Cargo.toml
├── README.md          ← You are here!
├── LICENSE
├── .gitignore
├── src/
│   ├── main.rs
│   ├── cli.rs
│   ├── config.rs
│   ├── service/
│   │   ├── mod.rs
│   │   └── lambda.rs
│   ├── tunnel/
│   │   └── manager.rs
│   └── router.rs      # Cloud router logic (if we ship a reference impl)
├── examples/
├── docs/
└── tests/
```

## Development Roadmap
**Phase 0: Setup (now)**
- Basic Cargo project + CLI skeleton

**Phase 1: Core Local Runner**
- Lambda local execution + tunnel

**Phase 2: Routing**
- Reference cloud router (Rust proxy or API Gateway authorizer)

**Phase 3: Polish**
- Config, auth, multiple services, UI feedback

**Phase 4: Extend**
- More runtimes, cloud providers, observability

## Getting Started
1. Clone the repo: `git clone https://github.com/math-s/ephemwork.git`
2. `cd ephemwork`
3. `cargo run -- --help` (once we have the skeleton)

Contributions welcome! Let's build the best local-dev experience for cloud-native apps.

---

*Last updated: May 2026*
