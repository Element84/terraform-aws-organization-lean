# -----------------------------------------------------------------------------
# Service Control Policies (SCPs)
#
# SCPs restrict what IAM principals inside member accounts can do. Importantly,
# note that they do not affect the management account.
#
# Staged: this folder is not loaded by the root module, so nothing here is
# applied. To apply a statement, work through its "Before promoting" note,
# then move it from here to /src/policies_scp.tf
# -----------------------------------------------------------------------------

locals {
  # Regions the region-deny SCP permits. allowed_regions is where workloads
  # are built. Two more are added here rather than in that variable:
  #   - us-east-1: CloudFront and other global services keep regional
  #     resources there (ACM certificates, Lambda@Edge).
  #   - the Security Hub aggregation region, so non-admins (OrgReadOnly, for
  #     example) can read and triage findings there.
  # Side effect: the SCP does not stop workloads in those two regions.
  scp_allowed_regions = setunion(
    var.allowed_regions,
    ["us-east-1", local.securityhub_aggregation_region],
  )

  # Global services and account-wide actions the region-deny SCP must not
  # block, because their requests are not made to a working region. Copied
  # on 2026-11-18 from AWS's example, which warns it may lack newer services:
  # https://github.com/aws-samples/service-control-policy-examples/tree/main/Region-controls
  scp_region_exempt_actions = [
    "a4b:*",
    "acm:*",
    "aws-marketplace-management:*",
    "aws-marketplace:*",
    "aws-portal:*",
    "budgets:*",
    "ce:*",
    "chime:*",
    "cloudfront:*",
    "config:*",
    "cur:*",
    "directconnect:*",
    "ec2:DescribeRegions",
    "ec2:DescribeTransitGateways",
    "ec2:DescribeVpnGateways",
    "fms:*",
    "globalaccelerator:*",
    "health:*",
    "iam:*",
    "importexport:*",
    "kms:*",
    "mobileanalytics:*",
    "networkmanager:*",
    "organizations:*",
    "pricing:*",
    "route53:*",
    "route53domains:*",
    "route53-recovery-cluster:*",
    "route53-recovery-control-config:*",
    "route53-recovery-readiness:*",
    "s3:GetAccountPublic*",
    "s3:ListAllMyBuckets",
    "s3:ListMultiRegionAccessPoints",
    "s3:PutAccountPublic*",
    "shield:*",
    "sts:*",
    "support:*",
    "trustedadvisor:*",
    "waf-regional:*",
    "waf:*",
    "wafv2:*",
    "wellarchitected:*",
  ]
}

# --- Baseline guardrails -----------------------------------------------------

resource "aws_organizations_policy" "scp_baseline" {
  name        = "${var.rsc_name}-scp-baseline-guardrails"
  description = "Staged SCP statements, not yet applied."
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Deny creating unencrypted EBS volumes, standalone or at instance
        # launch. Existing volumes are untouched.
        #
        # Before promoting: this is the one staged statement that can break
        # running workloads. Where EBS encryption-by-default is on, every new
        # volume is encrypted and the deny never fires, so:
        #
        # 1. Confirm encryption-by-default is on in every member account and
        #    region you use. Nothing in this repo enables it.
        #      aws ec2 get-ebs-encryption-by-default --region <region>
        #
        # 2. Where it is off, expect failures from anything that creates
        #    volumes with a customer IAM role: the EKS EBS CSI driver,
        #    Karpenter, EMR, older Batch compute environments, AWS Backup
        #    restores, and console launches from unencrypted AMIs.
        #    SCPs never apply to service-linked roles, so EC2 Auto Scaling
        #    groups (and EKS managed node groups) keep working, and can still
        #    launch unencrypted volumes.
        #
        # 3. Test in the Sandbox OU first. AWS docs imply, but do not state,
        #    that ec2:Encrypted is true when encryption-by-default supplies
        #    the flag. As a WorkloadDevelopers user, launch an unencrypted
        #    public AMI without the Encrypted flag. With default encryption
        #    on, expect success and an encrypted volume; with it off, expect
        #    UnauthorizedOperation. If you run EKS, also create a PVC with
        #    the default StorageClass and expect Bound.
        Sid      = "DenyUnencryptedEbsVolumes"
        Effect   = "Deny"
        Action   = ["ec2:CreateVolume", "ec2:RunInstances"]
        Resource = "arn:aws:ec2:*:*:volume/*"
        Condition = {
          Bool = {
            "ec2:Encrypted" = "false"
          }
        }
      },
      {
        # Prevent tampering with GuardDuty, CloudTrail, Config, Security Hub,
        # and Access Analyzer: disabling or deleting a service, and
        # suppressing its findings (archive rules, filters, automation rules,
        # publishing/import toggles). Suppression leaves the service green
        # while nobody sees what it finds.
        #
        # Admin principals are exempt so Terraform can still manage these
        # services. The delegated-admin resources live in the Audit account,
        # a member account, so this SCP covers them. It cannot reach the
        # management account.
        #
        # Deliberately allowed: securityhub:BatchUpdateFindings. The security
        # notification email tells recipients to mark findings NOTIFIED or
        # SUPPRESSED to stop repeat emails (service_securitynotifications.tf).
        #
        # Before promoting: nothing already running stops, but any non-admin
        # role that manages these services in a member account (a CI/CD role
        # with its own CloudTrail trail or Config recorder, for example)
        # fails on its next run. Non-admins also lose triage actions such as
        # guardduty:ArchiveFindings; that is intended.
        #
        # Search 90 days of CloudTrail in each workload account for the
        # actions below, excluding scp_admin_principals. For each role found,
        # either add it to scp_admin_principals (and say why) or warn its
        # owners first.
        Sid    = "ProtectSecurityServices"
        Effect = "Deny"
        Action = [
          "guardduty:ArchiveFindings",
          "guardduty:CreateFilter",
          "guardduty:DeleteDetector",
          "guardduty:DeleteInvitations",
          "guardduty:DeleteIPSet",
          "guardduty:DeleteMembers",
          "guardduty:DeletePublishingDestination",
          "guardduty:DeleteThreatIntelSet",
          "guardduty:DisassociateFromAdministratorAccount",
          "guardduty:DisassociateFromMasterAccount",
          "guardduty:DisassociateMembers",
          "guardduty:StopMonitoringMembers",
          "guardduty:UpdateDetector",
          "guardduty:UpdateFilter",
          "guardduty:UpdateOrganizationConfiguration",
          "guardduty:UpdatePublishingDestination",
          "cloudtrail:DeleteTrail",
          "cloudtrail:StopLogging",
          "cloudtrail:UpdateTrail",
          "cloudtrail:PutEventSelectors",
          "config:DeleteConfigurationRecorder",
          "config:DeleteDeliveryChannel",
          "config:PutConfigurationRecorder",
          "config:StopConfigurationRecorder",
          "securityhub:DisableSecurityHub",
          "securityhub:DisassociateFromAdministratorAccount",
          "securityhub:DisassociateMembers",
          "securityhub:DeleteMembers",
          "securityhub:UpdateOrganizationConfiguration",
          "securityhub:DeleteFindingAggregator",
          "securityhub:DisableImportFindingsForProduct",
          "securityhub:BatchDisableStandards",
          "securityhub:UpdateStandardsControl",
          "securityhub:CreateAutomationRule",
          "securityhub:BatchUpdateAutomationRules",
          "securityhub:BatchDeleteAutomationRules",
          "access-analyzer:DeleteAnalyzer",
          "access-analyzer:CreateArchiveRule",
          "access-analyzer:UpdateArchiveRule",
          "access-analyzer:DeleteArchiveRule",
          "access-analyzer:ApplyArchiveRule",
          "access-analyzer:UpdateFindings",
        ]
        Resource = "*"
        Condition = {
          ArnNotLike = {
            "aws:PrincipalArn" = local.scp_admin_principals
          }
        }
      },
    ]
  })
}

resource "aws_organizations_policy_attachment" "scp_baseline_root" {
  policy_id = aws_organizations_policy.scp_baseline.id
  target_id = local.org_root_id
}

# --- Region deny -------------------------------------------------------------

# Its own policy, not a statement in the baseline: an SCP is limited to 5,120
# characters and the exempt-action list is long. To promote, move this policy
# and its attachment to /src/policies_scp.tf.
resource "aws_organizations_policy" "scp_region_deny" {
  name        = "${var.rsc_name}-scp-region-deny"
  description = "Deny activity outside the allowed regions, except global services."
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Deny every request to a region outside scp_allowed_regions, apart
        # from the exempt global actions. Admin principals are exempt so
        # Terraform can manage GuardDuty and Access Analyzer in every region.
        #
        # Like every SCP, this does not cover the management account or
        # service-linked roles. GuardDuty's all-region coverage is what
        # watches for activity it cannot block.
        #
        # Before promoting:
        #
        # 1. Find what already runs in other regions. Anything there keeps
        #    running, but non-admins can no longer manage it, and any role
        #    that calls AWS in that region starts failing. Cost Explorer
        #    grouped by region, in each account, is the quickest check.
        #    Add the region to allowed_regions or move the workload first.
        #
        # 2. Review scp_region_exempt_actions against the services you use.
        #    A global service missing from it fails in every account. AWS
        #    publishes a variant for Bedrock cross-Region inference at the
        #    link above.
        #
        # 3. Attach to the Sandbox OU first and confirm that work in an
        #    allowed region succeeds, work in another region is denied, and
        #    IAM, Route 53, and billing pages still load.
        Sid       = "DenyOutsideAllowedRegions"
        Effect    = "Deny"
        NotAction = local.scp_region_exempt_actions
        Resource  = "*"
        Condition = {
          StringNotEquals = {
            "aws:RequestedRegion" = local.scp_allowed_regions
          }
          ArnNotLike = {
            "aws:PrincipalArn" = local.scp_admin_principals
          }
        }
      },
    ]
  })
}

resource "aws_organizations_policy_attachment" "scp_region_deny_root" {
  policy_id = aws_organizations_policy.scp_region_deny.id
  target_id = local.org_root_id
}
