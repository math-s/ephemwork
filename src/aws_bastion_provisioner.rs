//! Live `BastionProvisioner` impl backed by `aws-sdk-ec2` + `aws-sdk-iam`.
//!
//! Each method is idempotent: it looks up existing resources by name/tag
//! before creating, and tolerates "already exists" errors when racing.
//!
//! The trait is sync, so each method spins up an async block on the ambient
//! tokio runtime via `block_in_place`. The CLI uses `#[tokio::main]` so a
//! multi-threaded runtime is always present.
//!
//! There are no unit tests against AWS — the surface is covered by the
//! mock-driven orchestration tests in `bastion_provisioner.rs` and validated
//! end-to-end via a manual smoke test against a real account.

use crate::bastion_provisioner::{
    assume_role_policy_document, managed_policy_arns, BastionContext, BastionProvisioner,
    IngressSource, InstanceSummary, LaunchPlan, SecurityGroupPlan,
};
use anyhow::{anyhow, Context, Result};
use aws_sdk_ec2::types::{
    Filter, IpPermission, ResourceType, Tag, TagSpecification, UserIdGroupPair,
};
use aws_sdk_ec2::Client as Ec2Client;
use aws_sdk_iam::Client as IamClient;
use std::time::{Duration, Instant};
use tokio::runtime::Handle;
use tokio::task::block_in_place;

pub struct AwsBastionProvisioner {
    ec2: Ec2Client,
    iam: IamClient,
    handle: Handle,
    ctx: BastionContext,
}

impl AwsBastionProvisioner {
    pub async fn new(region: String, ctx: BastionContext) -> Result<Self> {
        let cfg = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new(region))
            .load()
            .await;
        Ok(Self {
            ec2: Ec2Client::new(&cfg),
            iam: IamClient::new(&cfg),
            handle: Handle::current(),
            ctx,
        })
    }

    fn block<F: std::future::Future>(&self, fut: F) -> F::Output {
        block_in_place(|| self.handle.block_on(fut))
    }

    async fn iam_role_exists(&self, name: &str) -> Result<bool> {
        use aws_sdk_iam::operation::get_role::GetRoleError;
        match self.iam.get_role().role_name(name).send().await {
            Ok(_) => Ok(true),
            Err(e) => match e.into_service_error() {
                GetRoleError::NoSuchEntityException(_) => Ok(false),
                other => Err(anyhow!("get_role failed: {other}")),
            },
        }
    }

    async fn instance_profile_exists(&self, name: &str) -> Result<bool> {
        use aws_sdk_iam::operation::get_instance_profile::GetInstanceProfileError;
        match self
            .iam
            .get_instance_profile()
            .instance_profile_name(name)
            .send()
            .await
        {
            Ok(_) => Ok(true),
            Err(e) => match e.into_service_error() {
                GetInstanceProfileError::NoSuchEntityException(_) => Ok(false),
                other => Err(anyhow!("get_instance_profile failed: {other}")),
            },
        }
    }

    async fn find_security_group_by_name(&self, name: &str) -> Result<Option<String>> {
        let resp = self
            .ec2
            .describe_security_groups()
            .filters(Filter::builder().name("group-name").values(name).build())
            .send()
            .await
            .context("describe_security_groups")?;
        Ok(resp
            .security_groups
            .and_then(|g| g.into_iter().next())
            .and_then(|g| g.group_id))
    }

    async fn vpc_id_for_security_group(&self, sg_id: &str) -> Result<String> {
        let resp = self
            .ec2
            .describe_security_groups()
            .group_ids(sg_id)
            .send()
            .await
            .context("describe_security_groups by id")?;
        let group = resp
            .security_groups
            .and_then(|g| g.into_iter().next())
            .ok_or_else(|| anyhow!("security group {sg_id} not found"))?;
        group
            .vpc_id
            .ok_or_else(|| anyhow!("security group {sg_id} has no VpcId"))
    }
}

impl BastionProvisioner for AwsBastionProvisioner {
    fn ensure_iam_role(&mut self) -> Result<()> {
        self.block(async {
            if !self.iam_role_exists(self.ctx.iam_role_name().as_str()).await? {
                self.iam
                    .create_role()
                    .role_name(self.ctx.iam_role_name().as_str())
                    .assume_role_policy_document(assume_role_policy_document())
                    .send()
                    .await
                    .context("create_role")?;
            }
            for arn in managed_policy_arns() {
                self.iam
                    .attach_role_policy()
                    .role_name(self.ctx.iam_role_name().as_str())
                    .policy_arn(arn)
                    .send()
                    .await
                    .with_context(|| format!("attach_role_policy {arn}"))?;
            }
            if !self
                .instance_profile_exists(self.ctx.iam_instance_profile_name().as_str())
                .await?
            {
                self.iam
                    .create_instance_profile()
                    .instance_profile_name(self.ctx.iam_instance_profile_name().as_str())
                    .send()
                    .await
                    .context("create_instance_profile")?;
                self.iam
                    .add_role_to_instance_profile()
                    .instance_profile_name(self.ctx.iam_instance_profile_name().as_str())
                    .role_name(self.ctx.iam_role_name().as_str())
                    .send()
                    .await
                    .context("add_role_to_instance_profile")?;
            }
            Ok(())
        })
    }

    fn ensure_security_group(&mut self, plan: &SecurityGroupPlan) -> Result<String> {
        use aws_sdk_ec2::error::ProvideErrorMetadata;

        self.block(async {
            // Look up first; create only if missing. Either way we then
            // reconcile ingress rules so a partially-created SG from a
            // prior failed run gets brought up to spec.
            let sg_id = match self.find_security_group_by_name(&plan.name).await? {
                Some(existing) => existing,
                None => {
                    let alb_sg = plan
                        .ingress
                        .iter()
                        .find_map(|r| match &r.source {
                            IngressSource::SecurityGroup(id) => Some(id.clone()),
                            IngressSource::Cidr(_) => None,
                        })
                        .ok_or_else(|| {
                            anyhow!("plan has no SG-source ingress to derive VPC from")
                        })?;
                    let vpc_id = self.vpc_id_for_security_group(&alb_sg).await?;
                    let create = self
                        .ec2
                        .create_security_group()
                        .group_name(plan.name.clone())
                        .description(plan.description.clone())
                        .vpc_id(vpc_id)
                        .send()
                        .await
                        .context("create_security_group")?;
                    create
                        .group_id
                        .ok_or_else(|| anyhow!("create_security_group returned no GroupId"))?
                }
            };

            for rule in &plan.ingress {
                let mut perm = IpPermission::builder()
                    .ip_protocol(rule.protocol)
                    .from_port(rule.from_port as i32)
                    .to_port(rule.to_port as i32);
                if let IngressSource::SecurityGroup(src_sg) = &rule.source {
                    perm = perm.user_id_group_pairs(
                        UserIdGroupPair::builder()
                            .group_id(src_sg)
                            .description(rule.description.to_string())
                            .build(),
                    );
                }
                let result = self
                    .ec2
                    .authorize_security_group_ingress()
                    .group_id(&sg_id)
                    .ip_permissions(perm.build())
                    .send()
                    .await;
                if let Err(e) = result {
                    let svc = e.into_service_error();
                    if svc.code() == Some("InvalidPermission.Duplicate") {
                        // Rule already present from a prior run — fine.
                    } else {
                        return Err(anyhow!("authorize_security_group_ingress failed: {svc}"));
                    }
                }
            }
            Ok(sg_id)
        })
    }

    fn launch_instance(&mut self, plan: &LaunchPlan) -> Result<String> {
        self.block(async {
            let tag_spec = build_tag_spec(&plan.tags);
            let resp = self
                .ec2
                .run_instances()
                .image_id(&plan.ami_id)
                .instance_type(plan.instance_type.as_str().into())
                .min_count(1)
                .max_count(1)
                .subnet_id(&plan.subnet_id)
                .security_group_ids(&plan.security_group_id)
                .iam_instance_profile(
                    aws_sdk_ec2::types::IamInstanceProfileSpecification::builder()
                        .name(&plan.instance_profile_name)
                        .build(),
                )
                .user_data(base64_encode(plan.user_data.as_bytes()))
                .tag_specifications(tag_spec)
                .send()
                .await
                .context("run_instances")?;
            let id = resp
                .instances
                .and_then(|v| v.into_iter().next())
                .and_then(|i| i.instance_id)
                .ok_or_else(|| anyhow!("run_instances returned no instance"))?;
            Ok(id)
        })
    }

    fn wait_until_running(&mut self, instance_id: &str) -> Result<()> {
        const TIMEOUT: Duration = Duration::from_secs(300);
        const POLL: Duration = Duration::from_secs(5);
        let deadline = Instant::now() + TIMEOUT;
        self.block(async {
            loop {
                let resp = self
                    .ec2
                    .describe_instances()
                    .instance_ids(instance_id)
                    .send()
                    .await
                    .context("describe_instances")?;
                let state = resp
                    .reservations
                    .and_then(|r| r.into_iter().next())
                    .and_then(|r| r.instances)
                    .and_then(|i| i.into_iter().next())
                    .and_then(|i| i.state)
                    .and_then(|s| s.name);
                if let Some(name) = state {
                    if name.as_str() == "running" {
                        return Ok(());
                    }
                }
                if Instant::now() >= deadline {
                    return Err(anyhow!(
                        "timed out waiting for {instance_id} to reach running"
                    ));
                }
                tokio::time::sleep(POLL).await;
            }
        })
    }

    fn find_instance_by_name(&mut self, name: &str) -> Result<Option<InstanceSummary>> {
        self.block(async {
            let resp = self
                .ec2
                .describe_instances()
                .filters(
                    Filter::builder()
                        .name("tag:Name")
                        .values(name.to_string())
                        .build(),
                )
                .filters(
                    Filter::builder()
                        .name("instance-state-name")
                        .values("pending")
                        .values("running")
                        .values("stopping")
                        .values("stopped")
                        .build(),
                )
                .send()
                .await
                .context("describe_instances by tag")?;
            let instance = resp
                .reservations
                .and_then(|r| r.into_iter().next())
                .and_then(|r| r.instances)
                .and_then(|i| i.into_iter().next());
            let Some(i) = instance else {
                return Ok(None);
            };
            let summary = InstanceSummary {
                instance_id: i.instance_id.unwrap_or_default(),
                state: i
                    .state
                    .and_then(|s| s.name)
                    .map(|s| s.as_str().to_string())
                    .unwrap_or_default(),
                private_ip: i.private_ip_address,
                security_group_id: i
                    .security_groups
                    .and_then(|sg| sg.into_iter().next())
                    .and_then(|sg| sg.group_id),
            };
            Ok(Some(summary))
        })
    }

    fn terminate_instance(&mut self, instance_id: &str) -> Result<()> {
        self.block(async {
            self.ec2
                .terminate_instances()
                .instance_ids(instance_id)
                .send()
                .await
                .context("terminate_instances")?;
            Ok(())
        })
    }

    fn delete_security_group(&mut self, sg_id: &str) -> Result<()> {
        self.block(async {
            self.ec2
                .delete_security_group()
                .group_id(sg_id)
                .send()
                .await
                .context("delete_security_group")?;
            Ok(())
        })
    }

    fn delete_iam_role(&mut self) -> Result<()> {
        self.block(async {
            // Reverse of ensure_iam_role: detach policies, remove from
            // instance profile, delete profile, delete role.
            if self
                .instance_profile_exists(self.ctx.iam_instance_profile_name().as_str())
                .await?
            {
                let _ = self
                    .iam
                    .remove_role_from_instance_profile()
                    .instance_profile_name(self.ctx.iam_instance_profile_name().as_str())
                    .role_name(self.ctx.iam_role_name().as_str())
                    .send()
                    .await;
                self.iam
                    .delete_instance_profile()
                    .instance_profile_name(self.ctx.iam_instance_profile_name().as_str())
                    .send()
                    .await
                    .context("delete_instance_profile")?;
            }
            if self.iam_role_exists(self.ctx.iam_role_name().as_str()).await? {
                for arn in managed_policy_arns() {
                    let _ = self
                        .iam
                        .detach_role_policy()
                        .role_name(self.ctx.iam_role_name().as_str())
                        .policy_arn(arn)
                        .send()
                        .await;
                }
                self.iam
                    .delete_role()
                    .role_name(self.ctx.iam_role_name().as_str())
                    .send()
                    .await
                    .context("delete_role")?;
            }
            Ok(())
        })
    }
}

fn build_tag_spec(tags: &[(String, String)]) -> TagSpecification {
    let aws_tags: Vec<Tag> = tags
        .iter()
        .map(|(k, v)| Tag::builder().key(k).value(v).build())
        .collect();
    TagSpecification::builder()
        .resource_type(ResourceType::Instance)
        .set_tags(Some(aws_tags))
        .build()
}

/// Minimal base64 encoder. AWS expects `user_data` to be base64-encoded;
/// we'd rather not pull in the `base64` crate just for this.
pub fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((input.len() + 2) / 3 * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        out.push(ALPHABET[(b0 >> 2) as usize] as char);
        out.push(ALPHABET[(((b0 & 0b11) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(((b1 & 0b1111) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(b2 & 0b111111) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_encode_matches_known_values() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn base64_encode_handles_binary() {
        // Bytes 0..255 round-trip via length, alphabet membership.
        let input: Vec<u8> = (0u8..=255).collect();
        let encoded = base64_encode(&input);
        // Length must be ceil(len/3)*4.
        let expected_len = ((input.len() + 2) / 3) * 4;
        assert_eq!(encoded.len(), expected_len);
        for c in encoded.chars() {
            assert!(
                c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=',
                "unexpected char {c:?}"
            );
        }
    }

    #[test]
    fn build_tag_spec_uses_instance_resource_type() {
        let tags = vec![
            ("Name".to_string(), "ephemwork-bastion".to_string()),
            ("ManagedBy".to_string(), "ephemwork".to_string()),
        ];
        let spec = build_tag_spec(&tags);
        assert_eq!(spec.resource_type(), Some(&ResourceType::Instance));
        let tags_out = spec.tags();
        assert_eq!(tags_out.len(), 2);
        assert!(tags_out.iter().any(|t| t.key() == Some("Name")));
        assert!(tags_out.iter().any(|t| t.key() == Some("ManagedBy")));
    }
}
