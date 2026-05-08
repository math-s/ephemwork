# ephemwork

A Rust CLI for selective local development in AWS cloud-native environments.

## Vision
Run **only** the service you're changing locally (ECS Fargate, Lambda, etc.), while the rest stays in staging. Route traffic via a simple HTTP header.

## Quick Start

```bash
ephemwork up backend
```

Then set header in requests:
```http
X-Ephemwork: YOUR_GITHUB_USERNAME:backend
```

## Current Focus
- AWS CDK stacks with ECS Fargate + Docker
- docker compose support for local runs
- Header-based routing to local tunnel

See full plan below.