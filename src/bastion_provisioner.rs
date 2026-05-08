//! Build the AWS resources that back the shared bastion.
//!
//! The flow has two layers:
//!   1. Pure plan builders — security-group rules, IAM trust policy,
//!      user-data script, instance tags. These are unit-tested without
//!      any AWS access.
//!   2. A `BastionProvisioner` trait whose AWS-SDK implementation is
//!      thin glue around the plan. Tests exercise the orchestration
//!      against an in-memory mock; the AWS impl is validated manually
//!      against a real account in commit 10's smoke test.

use crate::config::TunnelConfig;
use anyhow::{anyhow, Result};
use serde_json::json;
use std::collections::BTreeMap;

/// Resource names + tags used to look up existing bastion resources so
/// `bastion init` is idempotent.
pub const BASTION_NAME: &str = "ephemwork-bastion";
pub const SECURITY_GROUP_NAME: &str = "ephemwork-bastion-sg";
pub const IAM_ROLE_NAME: &str = "ephemwork-bastion-role";
pub const IAM_INSTANCE_PROFILE_NAME: &str = "ephemwork-bastion-instance-profile";

/// IAM trust policy that lets EC2 assume the bastion role. Returned as a
/// canonical JSON string so it round-trips identically through AWS.
pub fn assume_role_policy_document() -> String {
    let doc = json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": { "Service": "ec2.amazonaws.com" },
            "Action": "sts:AssumeRole"
        }]
    });
    serde_json::to_string(&doc).expect("static JSON must serialize")
}

/// Managed policies attached to the bastion role.
pub fn managed_policy_arns() -> Vec<&'static str> {
    vec![
        // Required for SSM Session Manager port forwarding (the laptop's
        // ssh-over-ssm route in to :22).
        "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
        // Required for the user-data script to fetch the bastion-server
        // binary from S3.
        "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
    ]
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityGroupPlan {
    pub name: String,
    pub description: String,
    /// Inbound rules. The bastion only accepts traffic on port 80 from the
    /// staging ALB; everything else gets in via SSM Session Manager which
    /// doesn't need an inbound rule on the bastion side.
    pub ingress: Vec<IngressRule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngressRule {
    pub protocol: &'static str,
    pub from_port: u16,
    pub to_port: u16,
    pub source: IngressSource,
    pub description: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngressSource {
    SecurityGroup(String),
    Cidr(String),
}

/// Build the plan for the bastion's security group given the staging ALB's
/// security group ID. We lock the only public-facing port (80) to traffic
/// coming from the ALB; all other access is via SSM.
pub fn security_group_plan(alb_security_group_id: &str) -> Result<SecurityGroupPlan> {
    if alb_security_group_id.trim().is_empty() {
        return Err(anyhow!("alb_security_group_id must not be empty"));
    }
    Ok(SecurityGroupPlan {
        name: SECURITY_GROUP_NAME.into(),
        description: "Inbound rules for the ephemwork bastion".into(),
        ingress: vec![IngressRule {
            protocol: "tcp",
            from_port: 80,
            to_port: 80,
            source: IngressSource::SecurityGroup(alb_security_group_id.into()),
            description: "ALB -> bastion nginx",
        }],
    })
}

/// Build the user-data script that installs nginx + the bastion-server
/// binary + systemd unit. The binary must be available at
/// `bastion_binary_s3_uri` (e.g. s3://my-bucket/ephemwork-bastion-server-arm64).
pub fn user_data_script(bastion_binary_s3_uri: &str) -> Result<String> {
    if !bastion_binary_s3_uri.starts_with("s3://") {
        return Err(anyhow!(
            "bastion_binary_s3_uri must be an s3:// URL, got {bastion_binary_s3_uri:?}"
        ));
    }
    Ok(format!(
        r#"#!/bin/bash
set -euxo pipefail

# Install nginx + AWS CLI (for fetching the bastion-server binary).
dnf install -y nginx awscli || yum install -y nginx awscli

# Layout for the bastion-server binary and its persistence.
install -d -m 0755 /opt/ephemwork
install -d -m 0755 /var/lib/ephemwork
install -d -m 0755 /etc/nginx/conf.d

# Pull the prebuilt arm64 binary the operator uploaded.
aws s3 cp "{s3_uri}" /opt/ephemwork/bastion-server
chmod 0755 /opt/ephemwork/bastion-server

# Stub config so nginx starts before any sessions exist.
cat > /etc/nginx/conf.d/ephemwork.conf <<'NGINX'
server {{
    listen 80 default_server;
    listen [::]:80 default_server;
    location = /ephemwork-health {{ return 200 "ok\n"; }}
    location / {{ return 404 "ephemwork bastion not yet configured\n"; }}
}}
NGINX
systemctl enable --now nginx

# Run the control plane as a system user, restart on crash.
cat > /etc/systemd/system/ephemwork-bastion.service <<'UNIT'
[Unit]
Description=ephemwork bastion control plane
After=network-online.target nginx.service
Wants=network-online.target

[Service]
ExecStart=/opt/ephemwork/bastion-server
Restart=always
RestartSec=2
Environment=EPHEMWORK_REGISTRY_PATH=/var/lib/ephemwork/registry.json
Environment=EPHEMWORK_NGINX_CONFIG=/etc/nginx/conf.d/ephemwork.conf
Environment=EPHEMWORK_NGINX_RELOAD=systemctl reload nginx
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now ephemwork-bastion.service
"#,
        s3_uri = bastion_binary_s3_uri
    ))
}

/// Tags applied to the launched instance so `bastion status`/`destroy` can
/// find it again.
pub fn instance_tags() -> BTreeMap<&'static str, &'static str> {
    let mut t = BTreeMap::new();
    t.insert("Name", BASTION_NAME);
    t.insert("ManagedBy", "ephemwork");
    t
}

/// Inputs for `BastionProvisioner::launch`. Everything the production code
/// needs to launch is here so tests can pin the values without going through
/// `aws-sdk-ec2` types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchPlan {
    pub region: String,
    pub instance_type: String,
    pub ami_id: String,
    pub subnet_id: String,
    pub security_group_id: String,
    pub instance_profile_name: String,
    pub user_data: String,
    pub tags: Vec<(String, String)>,
}

impl LaunchPlan {
    pub fn from_config(
        cfg: &TunnelConfig,
        ami_id: &str,
        subnet_id: &str,
        security_group_id: &str,
        bastion_binary_s3_uri: &str,
    ) -> Result<Self> {
        let user_data = user_data_script(bastion_binary_s3_uri)?;
        let tags = instance_tags()
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Ok(Self {
            region: cfg.region.clone(),
            instance_type: cfg.instance_type.clone(),
            ami_id: ami_id.into(),
            subnet_id: subnet_id.into(),
            security_group_id: security_group_id.into(),
            instance_profile_name: IAM_INSTANCE_PROFILE_NAME.into(),
            user_data,
            tags,
        })
    }
}

/// AWS calls the production provisioner needs to make. Split out so tests
/// can drive the orchestration with a mock and assert call ordering.
pub trait BastionProvisioner {
    fn ensure_security_group(&mut self, plan: &SecurityGroupPlan) -> Result<String>;
    fn ensure_iam_role(&mut self) -> Result<()>;
    fn launch_instance(&mut self, plan: &LaunchPlan) -> Result<String>;
    fn wait_until_running(&mut self, instance_id: &str) -> Result<()>;

    /// Look up the bastion instance by `Name` tag. Returns `None` if no
    /// instance is currently tagged with `BASTION_NAME`.
    fn find_instance_by_name(&mut self, name: &str) -> Result<Option<InstanceSummary>>;

    fn terminate_instance(&mut self, instance_id: &str) -> Result<()>;
    fn delete_security_group(&mut self, security_group_id: &str) -> Result<()>;
    fn delete_iam_role(&mut self) -> Result<()>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceSummary {
    pub instance_id: String,
    pub state: String,
    pub private_ip: Option<String>,
    pub security_group_id: Option<String>,
}

#[derive(Debug, Default)]
pub struct DestroyOutcome {
    pub instance_id: Option<String>,
    pub security_group_id: Option<String>,
}

/// Tear down the bastion in reverse order. Failure modes:
///   - No instance tagged BASTION_NAME: returns Ok with empty IDs (idempotent).
///   - SG removal failure: returned to caller; instance termination has
///     already happened so a re-run will skip it.
pub fn run_destroy(provisioner: &mut dyn BastionProvisioner) -> Result<DestroyOutcome> {
    let summary = provisioner.find_instance_by_name(BASTION_NAME)?;
    let Some(summary) = summary else {
        return Ok(DestroyOutcome::default());
    };
    provisioner.terminate_instance(&summary.instance_id)?;
    if let Some(sg_id) = &summary.security_group_id {
        provisioner.delete_security_group(sg_id)?;
    }
    provisioner.delete_iam_role()?;
    Ok(DestroyOutcome {
        instance_id: Some(summary.instance_id),
        security_group_id: summary.security_group_id,
    })
}

/// What `bastion status` reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BastionStatus {
    pub instance: Option<InstanceSummary>,
}

pub fn run_status(provisioner: &mut dyn BastionProvisioner) -> Result<BastionStatus> {
    let instance = provisioner.find_instance_by_name(BASTION_NAME)?;
    Ok(BastionStatus { instance })
}

pub fn render_bastion_status(status: &BastionStatus) -> String {
    match &status.instance {
        None => format!(
            "no bastion found (no instance tagged Name={BASTION_NAME}).\n\
             run `ephemwork bastion init --live ...` to provision one."
        ),
        Some(s) => {
            let ip = s.private_ip.as_deref().unwrap_or("?");
            let sg = s.security_group_id.as_deref().unwrap_or("?");
            format!(
                "bastion: {id}  state={state}  private_ip={ip}  sg={sg}\n\
                 (active sessions live in /var/lib/ephemwork/registry.json on the bastion)",
                id = s.instance_id,
                state = s.state,
            )
        }
    }
}

/// Dry-run provisioner: prints what *would* happen instead of calling AWS.
/// Used when `bastion init` runs without `--live`. Returns synthetic IDs so
/// the rest of the orchestration runs unchanged.
pub struct PlanLogger {
    pub log: Vec<String>,
}

impl PlanLogger {
    pub fn new() -> Self {
        Self { log: Vec::new() }
    }
}

impl Default for PlanLogger {
    fn default() -> Self {
        Self::new()
    }
}

impl BastionProvisioner for PlanLogger {
    fn ensure_security_group(&mut self, plan: &SecurityGroupPlan) -> Result<String> {
        self.log.push(format!(
            "[plan] ensure security group {:?} with {} ingress rule(s)",
            plan.name,
            plan.ingress.len()
        ));
        Ok("sg-DRYRUN".into())
    }
    fn ensure_iam_role(&mut self) -> Result<()> {
        self.log.push(format!(
            "[plan] ensure IAM role {:?} + instance profile {:?} with {} managed policies",
            IAM_ROLE_NAME,
            IAM_INSTANCE_PROFILE_NAME,
            managed_policy_arns().len()
        ));
        Ok(())
    }
    fn launch_instance(&mut self, plan: &LaunchPlan) -> Result<String> {
        self.log.push(format!(
            "[plan] launch {} in {} (subnet {}, ami {}) tagged Name={}",
            plan.instance_type,
            plan.region,
            plan.subnet_id,
            plan.ami_id,
            plan.tags
                .iter()
                .find(|(k, _)| k == "Name")
                .map(|(_, v)| v.as_str())
                .unwrap_or("?")
        ));
        Ok("i-DRYRUN".into())
    }
    fn wait_until_running(&mut self, instance_id: &str) -> Result<()> {
        self.log
            .push(format!("[plan] wait until {instance_id} is running"));
        Ok(())
    }
    fn find_instance_by_name(&mut self, name: &str) -> Result<Option<InstanceSummary>> {
        self.log
            .push(format!("[plan] look up instance tagged Name={name}"));
        Ok(Some(InstanceSummary {
            instance_id: "i-DRYRUN".into(),
            state: "running".into(),
            private_ip: Some("10.0.0.42".into()),
            security_group_id: Some("sg-DRYRUN".into()),
        }))
    }
    fn terminate_instance(&mut self, instance_id: &str) -> Result<()> {
        self.log
            .push(format!("[plan] terminate instance {instance_id}"));
        Ok(())
    }
    fn delete_security_group(&mut self, security_group_id: &str) -> Result<()> {
        self.log
            .push(format!("[plan] delete security group {security_group_id}"));
        Ok(())
    }
    fn delete_iam_role(&mut self) -> Result<()> {
        self.log.push(format!(
            "[plan] delete IAM role {IAM_ROLE_NAME} + instance profile {IAM_INSTANCE_PROFILE_NAME}"
        ));
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct InitOutcome {
    pub security_group_id: String,
    pub instance_id: String,
}

/// Drive a `BastionProvisioner` through the full init sequence. Pure
/// orchestration so the order of calls is testable.
pub fn run_init(
    provisioner: &mut dyn BastionProvisioner,
    sg_plan: &SecurityGroupPlan,
    launch_plan_for: impl FnOnce(&str) -> Result<LaunchPlan>,
) -> Result<InitOutcome> {
    provisioner.ensure_iam_role()?;
    let sg_id = provisioner.ensure_security_group(sg_plan)?;
    let plan = launch_plan_for(&sg_id)?;
    let instance_id = provisioner.launch_instance(&plan)?;
    provisioner.wait_until_running(&instance_id)?;
    Ok(InitOutcome {
        security_group_id: sg_id,
        instance_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> TunnelConfig {
        TunnelConfig {
            r#type: "ec2".into(),
            region: "us-east-1".into(),
            instance_type: "t4g.nano".into(),
        }
    }

    #[test]
    fn assume_role_policy_document_mentions_ec2_principal() {
        let s = assume_role_policy_document();
        assert!(s.contains("ec2.amazonaws.com"));
        assert!(s.contains("sts:AssumeRole"));
    }

    #[test]
    fn managed_policies_include_ssm_and_s3() {
        let p = managed_policy_arns();
        assert!(p.iter().any(|a| a.contains("AmazonSSMManagedInstanceCore")));
        assert!(p.iter().any(|a| a.contains("AmazonS3ReadOnlyAccess")));
    }

    #[test]
    fn security_group_plan_locks_port_80_to_alb_sg() {
        let plan = security_group_plan("sg-0123abc").unwrap();
        assert_eq!(plan.name, SECURITY_GROUP_NAME);
        assert_eq!(plan.ingress.len(), 1);
        let rule = &plan.ingress[0];
        assert_eq!(rule.protocol, "tcp");
        assert_eq!(rule.from_port, 80);
        assert_eq!(rule.to_port, 80);
        assert_eq!(
            rule.source,
            IngressSource::SecurityGroup("sg-0123abc".into())
        );
    }

    #[test]
    fn security_group_plan_rejects_empty_alb() {
        let err = security_group_plan("").unwrap_err().to_string();
        assert!(err.contains("alb_security_group_id"), "got: {err}");
    }

    #[test]
    fn user_data_script_requires_s3_uri() {
        let err = user_data_script("https://wrong").unwrap_err().to_string();
        assert!(err.contains("s3://"), "got: {err}");
    }

    #[test]
    fn user_data_script_includes_required_steps() {
        let s = user_data_script("s3://my-bucket/ephemwork-bastion-server").unwrap();
        assert!(s.contains("install -y nginx"));
        assert!(s.contains("aws s3 cp \"s3://my-bucket/ephemwork-bastion-server\""));
        assert!(s.contains("/opt/ephemwork/bastion-server"));
        assert!(s.contains("ephemwork-bastion.service"));
        assert!(s.contains("EPHEMWORK_REGISTRY_PATH"));
        assert!(s.contains("systemctl enable --now ephemwork-bastion.service"));
    }

    #[test]
    fn instance_tags_mark_managed_by_ephemwork() {
        let tags = instance_tags();
        assert_eq!(tags.get("Name"), Some(&BASTION_NAME));
        assert_eq!(tags.get("ManagedBy"), Some(&"ephemwork"));
    }

    #[test]
    fn launch_plan_packs_inputs() {
        let plan = LaunchPlan::from_config(
            &cfg(),
            "ami-1234",
            "subnet-abc",
            "sg-xyz",
            "s3://bucket/bin",
        )
        .unwrap();
        assert_eq!(plan.region, "us-east-1");
        assert_eq!(plan.instance_type, "t4g.nano");
        assert_eq!(plan.ami_id, "ami-1234");
        assert_eq!(plan.subnet_id, "subnet-abc");
        assert_eq!(plan.security_group_id, "sg-xyz");
        assert_eq!(plan.instance_profile_name, IAM_INSTANCE_PROFILE_NAME);
        assert!(plan.user_data.contains("s3://bucket/bin"));
        assert!(plan
            .tags
            .iter()
            .any(|(k, v)| k == "Name" && v == BASTION_NAME));
    }

    /// Records which methods were called and in what order so the
    /// orchestration is verifiable end-to-end.
    #[derive(Default)]
    struct MockProvisioner {
        calls: Vec<&'static str>,
        last_sg_plan: Option<SecurityGroupPlan>,
        last_launch_plan: Option<LaunchPlan>,
        instance_to_return: Option<InstanceSummary>,
    }
    impl BastionProvisioner for MockProvisioner {
        fn ensure_security_group(&mut self, plan: &SecurityGroupPlan) -> Result<String> {
            self.calls.push("ensure_security_group");
            self.last_sg_plan = Some(plan.clone());
            Ok("sg-mocked".into())
        }
        fn ensure_iam_role(&mut self) -> Result<()> {
            self.calls.push("ensure_iam_role");
            Ok(())
        }
        fn launch_instance(&mut self, plan: &LaunchPlan) -> Result<String> {
            self.calls.push("launch_instance");
            self.last_launch_plan = Some(plan.clone());
            Ok("i-mocked".into())
        }
        fn wait_until_running(&mut self, _instance_id: &str) -> Result<()> {
            self.calls.push("wait_until_running");
            Ok(())
        }
        fn find_instance_by_name(&mut self, _name: &str) -> Result<Option<InstanceSummary>> {
            self.calls.push("find_instance_by_name");
            Ok(self.instance_to_return.clone())
        }
        fn terminate_instance(&mut self, _instance_id: &str) -> Result<()> {
            self.calls.push("terminate_instance");
            Ok(())
        }
        fn delete_security_group(&mut self, _sg_id: &str) -> Result<()> {
            self.calls.push("delete_security_group");
            Ok(())
        }
        fn delete_iam_role(&mut self) -> Result<()> {
            self.calls.push("delete_iam_role");
            Ok(())
        }
    }

    #[test]
    fn run_init_orders_calls_correctly() {
        let mut prov = MockProvisioner::default();
        let sg_plan = security_group_plan("sg-alb").unwrap();
        let outcome = run_init(&mut prov, &sg_plan, |sg_id| {
            LaunchPlan::from_config(
                &cfg(),
                "ami-1234",
                "subnet-abc",
                sg_id,
                "s3://bucket/bin",
            )
        })
        .unwrap();
        assert_eq!(
            prov.calls,
            vec![
                "ensure_iam_role",
                "ensure_security_group",
                "launch_instance",
                "wait_until_running",
            ]
        );
        assert_eq!(outcome.security_group_id, "sg-mocked");
        assert_eq!(outcome.instance_id, "i-mocked");
        let launched = prov.last_launch_plan.unwrap();
        assert_eq!(launched.security_group_id, "sg-mocked");
    }

    #[test]
    fn plan_logger_records_each_step() {
        let mut logger = PlanLogger::new();
        let sg_plan = security_group_plan("sg-alb").unwrap();
        run_init(&mut logger, &sg_plan, |sg_id| {
            LaunchPlan::from_config(
                &cfg(),
                "ami-9999",
                "subnet-test",
                sg_id,
                "s3://bucket/bin",
            )
        })
        .unwrap();
        assert_eq!(logger.log.len(), 4);
        assert!(logger.log[0].contains("IAM role"));
        assert!(logger.log[1].contains("security group"));
        assert!(logger.log[2].contains("launch t4g.nano"));
        assert!(logger.log[2].contains("subnet-test"));
        assert!(logger.log[2].contains("ami-9999"));
        assert!(logger.log[3].contains("i-DRYRUN"));
    }

    #[test]
    fn run_init_propagates_iam_failure_without_launching() {
        struct Failing;
        impl BastionProvisioner for Failing {
            fn ensure_security_group(&mut self, _: &SecurityGroupPlan) -> Result<String> {
                panic!("must not be called")
            }
            fn ensure_iam_role(&mut self) -> Result<()> {
                Err(anyhow!("denied"))
            }
            fn launch_instance(&mut self, _: &LaunchPlan) -> Result<String> {
                panic!("must not be called")
            }
            fn wait_until_running(&mut self, _: &str) -> Result<()> {
                panic!("must not be called")
            }
            fn find_instance_by_name(&mut self, _: &str) -> Result<Option<InstanceSummary>> {
                panic!("must not be called")
            }
            fn terminate_instance(&mut self, _: &str) -> Result<()> {
                panic!("must not be called")
            }
            fn delete_security_group(&mut self, _: &str) -> Result<()> {
                panic!("must not be called")
            }
            fn delete_iam_role(&mut self) -> Result<()> {
                panic!("must not be called")
            }
        }
        let mut p = Failing;
        let sg_plan = security_group_plan("sg-alb").unwrap();
        let err = run_init(&mut p, &sg_plan, |_| panic!("must not be called"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("denied"), "got: {err}");
    }

    #[test]
    fn run_destroy_short_circuits_when_no_instance() {
        let mut p = MockProvisioner {
            instance_to_return: None,
            ..Default::default()
        };
        let outcome = run_destroy(&mut p).unwrap();
        assert!(outcome.instance_id.is_none());
        assert_eq!(p.calls, vec!["find_instance_by_name"]);
    }

    #[test]
    fn run_destroy_terminates_then_deletes_supporting_resources() {
        let mut p = MockProvisioner {
            instance_to_return: Some(InstanceSummary {
                instance_id: "i-real".into(),
                state: "running".into(),
                private_ip: Some("10.0.0.5".into()),
                security_group_id: Some("sg-real".into()),
            }),
            ..Default::default()
        };
        let outcome = run_destroy(&mut p).unwrap();
        assert_eq!(outcome.instance_id.as_deref(), Some("i-real"));
        assert_eq!(outcome.security_group_id.as_deref(), Some("sg-real"));
        assert_eq!(
            p.calls,
            vec![
                "find_instance_by_name",
                "terminate_instance",
                "delete_security_group",
                "delete_iam_role",
            ]
        );
    }

    #[test]
    fn run_destroy_skips_sg_when_summary_lacks_one() {
        let mut p = MockProvisioner {
            instance_to_return: Some(InstanceSummary {
                instance_id: "i-orphan".into(),
                state: "stopped".into(),
                private_ip: None,
                security_group_id: None,
            }),
            ..Default::default()
        };
        run_destroy(&mut p).unwrap();
        assert!(!p.calls.iter().any(|c| *c == "delete_security_group"));
        assert!(p.calls.iter().any(|c| *c == "delete_iam_role"));
    }

    #[test]
    fn run_status_returns_summary_when_present() {
        let mut p = MockProvisioner {
            instance_to_return: Some(InstanceSummary {
                instance_id: "i-99".into(),
                state: "running".into(),
                private_ip: Some("10.0.0.7".into()),
                security_group_id: Some("sg-99".into()),
            }),
            ..Default::default()
        };
        let s = run_status(&mut p).unwrap();
        assert_eq!(s.instance.as_ref().unwrap().instance_id, "i-99");
    }

    #[test]
    fn render_bastion_status_no_instance() {
        let s = render_bastion_status(&BastionStatus { instance: None });
        assert!(s.contains("no bastion found"));
        assert!(s.contains("ephemwork bastion init"));
    }

    #[test]
    fn render_bastion_status_with_instance() {
        let s = render_bastion_status(&BastionStatus {
            instance: Some(InstanceSummary {
                instance_id: "i-99".into(),
                state: "running".into(),
                private_ip: Some("10.0.0.7".into()),
                security_group_id: Some("sg-99".into()),
            }),
        });
        assert!(s.contains("i-99"));
        assert!(s.contains("running"));
        assert!(s.contains("10.0.0.7"));
        assert!(s.contains("sg-99"));
    }

    #[test]
    fn plan_logger_destroy_records_each_step() {
        let mut logger = PlanLogger::new();
        run_destroy(&mut logger).unwrap();
        assert!(logger.log.iter().any(|l| l.contains("look up instance")));
        assert!(logger.log.iter().any(|l| l.contains("terminate instance")));
        assert!(logger.log.iter().any(|l| l.contains("delete security group")));
        assert!(logger.log.iter().any(|l| l.contains("delete IAM role")));
    }
}
