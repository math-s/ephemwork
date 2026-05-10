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
use aws_sdk_ssm::Client as SsmClient;
use std::time::{Duration, Instant};
use tokio::runtime::Handle;
use tokio::task::block_in_place;

pub struct AwsBastionProvisioner {
    ec2: Ec2Client,
    iam: IamClient,
    ssm: SsmClient,
    handle: Handle,
    ctx: BastionContext,
}

/// Report from `AwsBastionProvisioner::ssm_agent_status` so `bastion
/// doctor` can render whether the bastion is reachable via SSM at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsmAgentInfo {
    pub ping_status: String,
    pub agent_version: Option<String>,
    pub last_ping: Option<String>,
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
            ssm: SsmClient::new(&cfg),
            handle: Handle::current(),
            ctx,
        })
    }

    /// Look up the bastion's SSM-agent registration. Returns `None` when
    /// the agent has never registered (so the laptop's port-forwards
    /// would error with `TargetNotConnected`).
    pub async fn ssm_agent_status(&self, instance_id: &str) -> Result<Option<SsmAgentInfo>> {
        use aws_sdk_ssm::types::InstanceInformationStringFilter;
        let resp = self
            .ssm
            .describe_instance_information()
            .filters(
                InstanceInformationStringFilter::builder()
                    .key("InstanceIds")
                    .values(instance_id)
                    .build()
                    .map_err(|e| anyhow!("filter build: {e}"))?,
            )
            .send()
            .await
            .with_context(|| format!("describe_instance_information {instance_id}"))?;
        let info = resp.instance_information_list.unwrap_or_default().into_iter().next();
        Ok(info.map(|i| SsmAgentInfo {
            ping_status: i
                .ping_status
                .map(|s| s.as_str().to_string())
                .unwrap_or_else(|| "Unknown".into()),
            agent_version: i.agent_version,
            last_ping: i.last_ping_date_time.map(|t| t.to_string()),
        }))
    }

    fn block<F: std::future::Future>(&self, fut: F) -> F::Output {
        block_in_place(|| self.handle.block_on(fut))
    }

    /// Enumerate interface VPC endpoints in `vpc_id` whose security
    /// groups don't allow inbound :443 from `bastion_sg_id`. Run after
    /// `bastion init --live` to catch the silent SSM-can't-reach-endpoint
    /// failure mode early instead of after a 5-minute "instance never
    /// joined SSM" wait.
    pub async fn missing_vpc_endpoint_ingress(
        &self,
        vpc_id: &str,
        bastion_sg_id: &str,
    ) -> Result<Vec<MissingEndpointIngress>> {
        use aws_sdk_ec2::types::VpcEndpointType;

        let resp = self
            .ec2
            .describe_vpc_endpoints()
            .filters(Filter::builder().name("vpc-id").values(vpc_id).build())
            .send()
            .await
            .with_context(|| format!("describe_vpc_endpoints {vpc_id}"))?;

        let endpoints = resp.vpc_endpoints.unwrap_or_default();
        // De-dupe SG IDs across endpoints so we issue one
        // describe_security_groups per group, not one per endpoint.
        let mut groups_to_check: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        for ep in &endpoints {
            if ep.vpc_endpoint_type != Some(VpcEndpointType::Interface) {
                continue;
            }
            let service = ep.service_name.clone().unwrap_or_default();
            for group in ep.groups.clone().unwrap_or_default() {
                if let Some(gid) = group.group_id {
                    groups_to_check.entry(gid).or_insert_with(|| service.clone());
                }
            }
        }

        let mut missing = Vec::new();
        for (sg_id, service) in groups_to_check {
            let perms = self.security_group_ingress(&sg_id).await?;
            if !ingress_allows(&perms, bastion_sg_id, 443) {
                missing.push(MissingEndpointIngress {
                    endpoint_sg_id: sg_id,
                    endpoint_service: service,
                    port: 443,
                });
            }
        }
        // Stable order so the printed warnings don't shuffle between runs.
        missing.sort_by(|a, b| {
            a.endpoint_service
                .cmp(&b.endpoint_service)
                .then_with(|| a.endpoint_sg_id.cmp(&b.endpoint_sg_id))
        });
        Ok(missing)
    }

    async fn security_group_ingress(
        &self,
        sg_id: &str,
    ) -> Result<Vec<aws_sdk_ec2::types::IpPermission>> {
        let resp = self
            .ec2
            .describe_security_groups()
            .group_ids(sg_id)
            .send()
            .await
            .with_context(|| format!("describe_security_groups {sg_id}"))?;
        let group = resp
            .security_groups
            .and_then(|v| v.into_iter().next())
            .ok_or_else(|| anyhow!("security group {sg_id} not found"))?;
        Ok(group.ip_permissions.unwrap_or_default())
    }

    /// Look up which VPC the subnet lives in. Used by the prod-safety guard
    /// in `bastion init --live` to refuse a subnet from the wrong VPC before
    /// any resource is created.
    pub async fn vpc_id_for_subnet(&self, subnet_id: &str) -> Result<String> {
        let resp = self
            .ec2
            .describe_subnets()
            .subnet_ids(subnet_id)
            .send()
            .await
            .with_context(|| format!("describe_subnets {subnet_id}"))?;
        resp.subnets
            .and_then(|v| v.into_iter().next())
            .and_then(|s| s.vpc_id)
            .ok_or_else(|| anyhow!("subnet {subnet_id} not found"))
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

/// One VPC endpoint whose security group doesn't allow inbound from the
/// bastion's SG. The bastion's SSM agent (and any other service that
/// resolves a public hostname to a private interface endpoint via VPC
/// DNS) silently fails until the missing rule is added.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingEndpointIngress {
    /// Security group attached to the endpoint's ENI.
    pub endpoint_sg_id: String,
    /// Service the endpoint exposes (e.g. `com.amazonaws.us-east-1.ssm`).
    pub endpoint_service: String,
    /// Port the bastion needs to reach the endpoint on (always 443 for
    /// AWS interface endpoints today, kept here for clarity in error
    /// messages).
    pub port: u16,
}

impl MissingEndpointIngress {
    /// Render the exact `aws ec2 authorize-security-group-ingress` command
    /// the operator should run. Designed to be copy-pasted into a shell.
    pub fn fix_command(&self, bastion_sg_id: &str, profile: Option<&str>) -> String {
        let profile_arg = profile
            .map(|p| format!(" --profile {p}"))
            .unwrap_or_default();
        format!(
            "aws ec2 authorize-security-group-ingress{profile_arg} \\\n  \
               --group-id {endpoint_sg} \\\n  \
               --ip-permissions 'IpProtocol=tcp,FromPort={port},ToPort={port},\
                                 UserIdGroupPairs=[{{GroupId={bastion_sg},Description=\"ephemwork bastion\"}}]'",
            endpoint_sg = self.endpoint_sg_id,
            port = self.port,
            bastion_sg = bastion_sg_id,
        )
    }
}

/// Pure check: given an SG's ingress permissions, does any of them allow
/// `port` from `source_sg_id`? Public so tests pin the rule semantics
/// without touching the AWS SDK.
pub fn ingress_allows(
    perms: &[aws_sdk_ec2::types::IpPermission],
    source_sg_id: &str,
    port: u16,
) -> bool {
    let port_i = port as i32;
    for p in perms {
        if p.ip_protocol() != Some("tcp") {
            continue;
        }
        let from = p.from_port().unwrap_or(-1);
        let to = p.to_port().unwrap_or(-1);
        if from > port_i || to < port_i {
            continue;
        }
        if p
            .user_id_group_pairs()
            .iter()
            .any(|pair| pair.group_id() == Some(source_sg_id))
        {
            return true;
        }
    }
    false
}

/// Pure check for the prod-safety guard. Public so tests can pin the error
/// shape without making any AWS calls.
pub fn verify_vpc_match(subnet_id: &str, actual_vpc: &str, expected_vpc: &str) -> Result<()> {
    if actual_vpc != expected_vpc {
        return Err(anyhow!(
            "refusing to provision: subnet {subnet_id} is in {actual_vpc} but \
             ephemwork.toml pins tunnel.expected_vpc_id = {expected_vpc}. Aborting \
             before any AWS resource is created."
        ));
    }
    Ok(())
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
    fn ingress_allows_matches_exact_port_and_sg() {
        use aws_sdk_ec2::types::{IpPermission, UserIdGroupPair};
        let perm = IpPermission::builder()
            .ip_protocol("tcp")
            .from_port(443)
            .to_port(443)
            .user_id_group_pairs(
                UserIdGroupPair::builder().group_id("sg-bastion").build(),
            )
            .build();
        assert!(ingress_allows(&[perm.clone()], "sg-bastion", 443));
        assert!(!ingress_allows(&[perm.clone()], "sg-other", 443));
        assert!(!ingress_allows(&[perm], "sg-bastion", 5432));
    }

    #[test]
    fn ingress_allows_matches_inside_port_range() {
        use aws_sdk_ec2::types::{IpPermission, UserIdGroupPair};
        let perm = IpPermission::builder()
            .ip_protocol("tcp")
            .from_port(400)
            .to_port(500)
            .user_id_group_pairs(
                UserIdGroupPair::builder().group_id("sg-bastion").build(),
            )
            .build();
        assert!(ingress_allows(&[perm.clone()], "sg-bastion", 443));
        assert!(!ingress_allows(&[perm], "sg-bastion", 501));
    }

    #[test]
    fn ingress_allows_rejects_non_tcp() {
        use aws_sdk_ec2::types::{IpPermission, UserIdGroupPair};
        let udp = IpPermission::builder()
            .ip_protocol("udp")
            .from_port(443)
            .to_port(443)
            .user_id_group_pairs(
                UserIdGroupPair::builder().group_id("sg-bastion").build(),
            )
            .build();
        assert!(!ingress_allows(&[udp], "sg-bastion", 443));
    }

    #[test]
    fn ingress_allows_rejects_cidr_only_rule() {
        use aws_sdk_ec2::types::{IpPermission, IpRange};
        let perm = IpPermission::builder()
            .ip_protocol("tcp")
            .from_port(443)
            .to_port(443)
            .ip_ranges(IpRange::builder().cidr_ip("10.0.0.0/8").build())
            .build();
        // CIDR-only rules don't grant SG access.
        assert!(!ingress_allows(&[perm], "sg-bastion", 443));
    }

    #[test]
    fn missing_endpoint_ingress_renders_copy_pasteable_fix() {
        let m = MissingEndpointIngress {
            endpoint_sg_id: "sg-endpoint".into(),
            endpoint_service: "com.amazonaws.us-east-1.ssm".into(),
            port: 443,
        };
        let cmd = m.fix_command("sg-bastion", Some("motocred"));
        assert!(cmd.starts_with("aws ec2 authorize-security-group-ingress"));
        assert!(cmd.contains("--profile motocred"));
        assert!(cmd.contains("--group-id sg-endpoint"));
        assert!(cmd.contains("FromPort=443,ToPort=443"));
        assert!(cmd.contains("GroupId=sg-bastion"));
    }

    #[test]
    fn missing_endpoint_ingress_omits_profile_when_unset() {
        let m = MissingEndpointIngress {
            endpoint_sg_id: "sg-x".into(),
            endpoint_service: "any".into(),
            port: 443,
        };
        let cmd = m.fix_command("sg-y", None);
        assert!(!cmd.contains("--profile"));
    }

    #[test]
    fn verify_vpc_match_accepts_same_vpc() {
        verify_vpc_match("subnet-x", "vpc-1", "vpc-1").unwrap();
    }

    #[test]
    fn verify_vpc_match_rejects_different_vpc_with_explicit_message() {
        let err = verify_vpc_match("subnet-prod", "vpc-prod", "vpc-staging")
            .unwrap_err()
            .to_string();
        assert!(err.contains("subnet-prod"), "got: {err}");
        assert!(err.contains("vpc-prod"), "got: {err}");
        assert!(err.contains("vpc-staging"), "got: {err}");
        assert!(err.contains("expected_vpc_id"), "got: {err}");
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
