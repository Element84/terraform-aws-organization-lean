# -----------------------------------------------------------------------------
# Service Control Policies (SCPs)
#
# SCPs restrict what IAM principals inside member accounts can do. They do
# not affect the management account, and they never apply to service-linked
# roles.
# -----------------------------------------------------------------------------

locals {
  # Principals exempt from the tamper-protection statements below: the
  # cross-account admin/Terraform role and the Identity Center
  # OrgAdministrator permission-set roles.
  # The SSO pattern is built from local.sso_admin_permission_set_name
  # (locals.tf), which also names the permission set itself
  # (staged/service_identitycenter.tf), so the two cannot drift apart.
  # aws:PrincipalArn for an assumed-role session resolves to the ROLE arn, so
  # these patterns match. The leading * in the SSO pattern absorbs the
  # optional region segment in the role path.
  scp_admin_principals = [
    "arn:aws:iam::*:role/${local.org_access_role}",
    "arn:aws:iam::*:role/aws-reserved/sso.amazonaws.com/*AWSReservedSSO_${local.sso_admin_permission_set_name}_*",
  ]

  # Control-plane roles protected from IAM tampering. Identity Center manages
  # AWSReservedSSO_* roles via its service-linked role, and SCPs don't apply
  # to service-linked roles, so permission-set provisioning is unaffected.
  scp_protected_role_arns = [
    "arn:aws:iam::*:role/${local.org_access_role}",
    "arn:aws:iam::*:role/aws-reserved/sso.amazonaws.com/*",
  ]
}

# --- Baseline guardrails -----------------------------------------------------

resource "aws_organizations_policy" "scp_baseline" {
  name        = "${var.rsc_name}-scp-baseline-guardrails"
  description = "Deny root user actions (AssumeRoot exempt), leaving the org, disabling EBS default encryption, region opt-in changes, and control-plane role modification. See src/staged/policies_scp.tf for statements not yet applied."
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Deny root user actions in member accounts, *unless* the Management
        # account is assuming root. That is our break-glass path.
        Sid      = "DenyRootUserActions"
        Effect   = "Deny"
        Action   = "*"
        Resource = "*"
        Condition = {
          ArnLike = {
            "aws:PrincipalArn" = [
              "arn:aws:iam::*:root"
            ]
          },
          Null = {
            "aws:AssumedRoot" : "true"
          }
        }
      },
      {
        # Don't allow member accounts to leave the organization.
        Sid      = "DenyLeavingOrganization"
        Effect   = "Deny"
        Action   = "organizations:LeaveOrganization"
        Resource = "*"
      },
      {
        # Lock the per-region EBS encryption-by-default setting against being
        # turned off. This statement enables nothing: an account/region where
        # the setting is currently off stays off, and anyone may still turn it
        # on. It only removes the ability to disable it from non-admins.
        Sid      = "DenyDisablingEbsDefaultEncryption"
        Effect   = "Deny"
        Action   = "ec2:DisableEbsEncryptionByDefault"
        Resource = "*"
        Condition = {
          ArnNotLike = {
            "aws:PrincipalArn" = local.scp_admin_principals
          }
        }
      },
      {
        # Lock the account-level region opt-in toggle (managed in
        # modules/account). Limiting which regions can be used is a separate,
        # staged SCP: see staged/policies_scp.tf.
        Sid      = "PreventRegionOptInChanges"
        Effect   = "Deny"
        Action   = ["account:EnableRegion", "account:DisableRegion"]
        Resource = "*"
        Condition = {
          ArnNotLike = {
            "aws:PrincipalArn" = local.scp_admin_principals
          }
        }
      },
      {
        # Protect control-plane roles (OrganizationAccountAccessRole, Identity
        # Center permission-set roles) from IAM tampering.
        Sid    = "PreventCriticalRoleModification"
        Effect = "Deny"
        Action = [
          "iam:AttachRolePolicy",
          "iam:DeleteRole",
          "iam:DeleteRolePermissionsBoundary",
          "iam:DeleteRolePolicy",
          "iam:DetachRolePolicy",
          "iam:PutRolePermissionsBoundary",
          "iam:PutRolePolicy",
          "iam:UpdateRole",
          "iam:UpdateRoleDescription",
          "iam:UpdateAssumeRolePolicy",
        ]
        Resource = local.scp_protected_role_arns
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
