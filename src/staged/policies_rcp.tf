# -----------------------------------------------------------------------------
# Resource Control Policies (RCPs)
#
# RCPs cap the permissions available on *resources* in member accounts,
# whoever the caller is (including external principals). Like SCPs, they do
# not affect the management account. AWS also never applies them to
# service-linked roles (or to AWS services assuming those roles) or to
# AWS-managed KMS keys.
# -----------------------------------------------------------------------------

locals {
  # Services this RCP governs: a deliberate subset of what RCPs support (44
  # services at the last sync, 2026-09-07; AWS keeps adding more):
  # https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html
  # Every entry is subject to all three statements below (identity
  # perimeter, confused-deputy protection, TLS enforcement), so add a service
  # only after checking that nothing legitimately calls it anonymously or
  # from outside the org. For sts:*, the identity perimeter uses a narrower
  # list; see rcp_identity_perimeter_actions.
  #
  # The set matches the AWS data-perimeter reference policy
  # (aws-samples/data-perimeter-policy-examples,
  # resource_control_policies/identity_perimeter_rcp.json) minus aoss
  # (OpenSearch Serverless; add it if you use it).
  #
  # Deliberately excluded: cognito-identity. Identity-pool guest flows call
  # GetId/GetCredentialsForIdentity unauthenticated by design, and the
  # identity perimeter denies anonymous callers. AWS's reference policy
  # includes it only in the confused-deputy statement for this reason.
  # cognito-idp (user pools) is safe to include: its unauthenticated calls
  # (InitiateAuth, SignUp, ...) are not IAM-authorized, so RCPs never
  # evaluate them.
  rcp_services = [
    "s3:*",
    "sts:*",
    "sqs:*",
    "secretsmanager:*",
    "kms:*",
    "dynamodb:*",
    "ecr:*",
    "logs:*",
    "cognito-idp:*",
  ]

  # Actions covered by the identity perimeter: rcp_services, with sts:*
  # replaced by the STS actions only ever called by authenticated principals
  # (the same list as AWS's reference policy). sts:* wholesale would also
  # catch the federation entry points. Those are called unauthenticated (no
  # aws:PrincipalOrgID, not an AWS service), so the perimeter's ...IfExists
  # conditions would match and deny them:
  #  - sts:AssumeRoleWithSAML: every Identity Center sign-in to a member
  #    account. The AWSReservedSSO_* roles trust the AWSSSO-managed SAML
  #    provider through this action, so including it breaks SSO org-wide.
  #    This RCP leaves it ungoverned; role trust policies control it.
  #  - sts:AssumeRoleWithWebIdentity: GitHub Actions OIDC and EKS IRSA.
  #    Governed separately via rcp_trusted_oidc_tenants below.
  # sts:* stays in the other two statements. Confused-deputy only matches
  # AWS-service callers (Bool, not BoolIfExists) and the TLS statement only
  # matches non-TLS requests, so neither can fire on federation.
  rcp_identity_perimeter_actions = concat(
    [for s in local.rcp_services : s if s != "sts:*"],
    [
      "sts:AssumeRole",
      "sts:DecodeAuthorizationMessage",
      "sts:GetAccessKeyInfo",
      "sts:GetFederationToken",
      "sts:GetServiceBearerToken",
      "sts:GetSessionToken",
      "sts:SetContext",
    ],
  )

  # Web-identity (OIDC) providers trusted to assume roles in member
  # accounts, keyed by provider domain (the token's condition-key prefix),
  # with StringLike patterns for the subjects (:sub claim) each provider may
  # present. Hardcoded, not a variable: trusting an external identity
  # provider is security-sensitive, so adding one should be a reviewed code
  # change. Example, for GitHub Actions CI/CD plus an EKS cluster using IRSA:
  #   "token.actions.githubusercontent.com"         = ["repo:example-org/*"]
  #   "oidc.eks.us-west-2.amazonaws.com/id/EXAMPLE" = ["system:serviceaccount:*"]
  #
  # Any entry here turns on deny-by-default: once this policy is promoted,
  # roles in member accounts can be assumed only through the providers and
  # subjects listed. The map ships with one entry so that is the default.
  # An empty map emits no web-identity statements, leaving role trust
  # policies as the only control.
  #
  # Before promoting: the list must be complete. EKS IRSA uses one OIDC
  # provider per cluster, so a cluster missing from this map has every IRSA
  # service account broken the moment the policy applies. Inventory existing
  # providers (aws iam list-open-id-connect-providers in each account) and
  # declare all of them.
  #
  # The entry below lets this repository's GitHub workflows assume roles in
  # member accounts. It does not protect the deploy role in service_iam.tf:
  # that role is in the management account, which RCPs do not affect, so its
  # own trust policy is its only guard.
  #
  # TODO: replace the organization, the repository, and the numeric GitHub ID
  # after each with your own.
  rcp_trusted_oidc_tenants = {
    "token.actions.githubusercontent.com" = ["repo:example-org@12345678/terraform-aws-organization-lean@1234567890:*"]
  }

  # Principal ARN patterns exempt from the identity perimeter. Hardcoded, not
  # a variable: exemptions are security-sensitive and rare, so adding one
  # should be a reviewed code change. Add an entry when a trusted third
  # party (e.g. a SaaS vendor) must assume a role or access resources in our
  # accounts, for example:
  #   "arn:aws:iam::123456789012:role/DatadogIntegrationRole"
  rcp_exempt_principal_arns = []
}

resource "aws_organizations_policy" "rcp_baseline" {
  name        = "${var.rsc_name}-rcp-baseline"
  description = "Org identity perimeter, confused-deputy protection, and TLS enforcement on RCP-supported services."
  type        = "RESOURCE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        # Identity perimeter: only principals in THIS org may access our
        # resources (AWS services acting on our behalf are handled by the
        # next statement). This also blocks anonymous/public access, since
        # anonymous callers have no aws:PrincipalOrgID. Exempt third-party
        # integrations via local.rcp_exempt_principal_arns.
        # Deliberately not sts:*; see rcp_identity_perimeter_actions.
        Sid       = "EnforceOrgIdentityPerimeter"
        Effect    = "Deny"
        Principal = "*"
        Action    = local.rcp_identity_perimeter_actions
        Resource  = "*"
        Condition = merge(
          {
            StringNotEqualsIfExists = {
              "aws:PrincipalOrgID" = aws_organizations_organization.this.id
            }
            BoolIfExists = {
              "aws:PrincipalIsAWSService" = "false"
            }
          },
          length(local.rcp_exempt_principal_arns) > 0 ? {
            ArnNotLikeIfExists = {
              "aws:PrincipalArn" = local.rcp_exempt_principal_arns
            }
          } : {}
        )
      },
      {
        # Confused-deputy protection for the AWS-service calls the statement
        # above exempts: when a service call carries source-account context,
        # the source must be inside this org. Calls with no SourceAccount
        # (e.g. CloudTrail log delivery) aren't matched, so internal service
        # operations keep working.
        Sid       = "EnforceConfusedDeputyProtection"
        Effect    = "Deny"
        Principal = "*"
        Action    = local.rcp_services
        Resource  = "*"
        Condition = {
          StringNotEqualsIfExists = {
            "aws:SourceOrgID" = aws_organizations_organization.this.id
          }
          Bool = {
            "aws:PrincipalIsAWSService" = "true"
          }
          Null = {
            "aws:SourceAccount" = "false"
          }
        }
      },
      {
        # Deny any request not made over TLS.
        Sid       = "EnforceSecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = local.rcp_services
        Resource  = "*"
        Condition = {
          BoolIfExists = {
            "aws:SecureTransport" = "false"
          }
        }
      },
      ],
      # Web-identity federation guardrail, emitted only when
      # rcp_trusted_oidc_tenants is populated (see that local for why).
      # Two layers, mirroring AWS's reference policy: deny
      # sts:AssumeRoleWithWebIdentity from any undeclared provider, then
      # per declared provider deny subjects outside its patterns.
      # (The for-guard emits zero or one statement; a plain ternary can't
      # hold these differently-shaped objects without a type mismatch.)
      [
        for emit in(length(local.rcp_trusted_oidc_tenants) > 0 ? [1] : []) : {
          # A token from a declared provider carries that provider's :sub
          # condition key; a token from any other provider carries none of
          # them, so every Null test is true and the deny fires.
          Sid       = "EnforceTrustedOIDCProviders"
          Effect    = "Deny"
          Principal = "*"
          Action    = "sts:AssumeRoleWithWebIdentity"
          Resource  = "*"
          Condition = {
            Null = {
              for provider in keys(local.rcp_trusted_oidc_tenants) :
              "${provider}:sub" => "true"
            }
          }
        }
      ],
      [
        for i, provider in keys(local.rcp_trusted_oidc_tenants) : {
          # Token is from this provider (:sub present) but the subject
          # matches none of the allowed patterns.
          Sid       = "EnforceTrustedOIDCTenants${i}"
          Effect    = "Deny"
          Principal = "*"
          Action    = "sts:AssumeRoleWithWebIdentity"
          Resource  = "*"
          Condition = {
            StringNotLike = {
              "${provider}:sub" = local.rcp_trusted_oidc_tenants[provider]
            }
            Null = {
              "${provider}:sub" = "false"
            }
          }
        }
      ],
    )
  })
}

resource "aws_organizations_policy_attachment" "rcp_baseline_root" {
  policy_id = aws_organizations_policy.rcp_baseline.id
  target_id = local.org_root_id
}
