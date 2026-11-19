# -----------------------------------------------------------------------------
# Declarative Policies
#
# Declarative policies enforce a desired configuration state at the service
# level - the settings below are locked org-wide and cannot be changed from
# inside member accounts.
# -----------------------------------------------------------------------------

resource "aws_organizations_policy" "dec_ec2_baseline" {
  name        = "${var.rsc_name}-dec-ec2-baseline"
  description = "Org-wide EC2 security baseline: IMDSv2 required, no public AMI or snapshot sharing, serial console disabled."
  type        = "DECLARATIVE_POLICY_EC2"

  content = jsonencode({
    ec2_attributes = {
      # VPC Block Public Access: block inbound-from-internet org-wide while
      # still allowing outbound via NAT / egress-only IGW. The mode is locked
      # centrally, but exclusions_allowed = enabled lets an account that
      # genuinely needs a public-facing subnet/VPC (e.g. a public ALB) opt
      # back in with aws_vpc_block_public_access_exclusion, created locally
      # in that account alongside its workload Terraform.
      vpc_block_public_access = {
        internet_gateway_block = {
          mode = {
            "@@assign" = "block_ingress"
          }
          exclusions_allowed = {
            "@@assign" = "enabled"
          }
        }
      }

      # Require IMDSv2 on all new instances.
      instance_metadata_defaults = {
        http_tokens = {
          "@@assign" = "required"
        }
        http_put_response_hop_limit = {
          "@@assign" = "2"
        }
        http_endpoint = {
          "@@assign" = "enabled"
        }
        instance_metadata_tags = {
          "@@assign" = "no_preference"
        }
      }

      # Block making AMIs public.
      image_block_public_access = {
        state = {
          "@@assign" = "block_new_sharing"
        }
      }

      # Block making EBS snapshots public.
      snapshot_block_public_access = {
        state = {
          "@@assign" = "block_all_sharing"
        }
      }

      # Disable the EC2 serial console.
      serial_console_access = {
        status = {
          "@@assign" = "disabled"
        }
      }
    }
  })
}

resource "aws_organizations_policy_attachment" "dec_ec2_baseline_root" {
  policy_id = aws_organizations_policy.dec_ec2_baseline.id
  target_id = local.org_root_id
}

# -----------------------------------------------------------------------------
# S3 management policy: org-wide S3 Block Public Access
#
# "all" enables all four account-level BPA settings in every account,
# overrides account-level settings, and is inherited by new accounts.
# Storage-layer companion to the VPC BPA and the identity perimeter RCP:
# intentionally-public buckets become impossible; serve public content via
# CloudFront instead (the staged region-deny SCP allows us-east-1 for exactly this).
# -----------------------------------------------------------------------------

resource "aws_organizations_policy" "dec_s3_baseline" {
  name        = "${var.rsc_name}-dec-s3-baseline"
  description = "Org-wide S3 Block Public Access (all four settings)."
  type        = "S3_POLICY"

  content = jsonencode({
    s3_attributes = {
      public_access_block_configuration = {
        "@@assign" = "all"
      }
    }
  })
}

resource "aws_organizations_policy_attachment" "dec_s3_baseline_root" {
  policy_id = aws_organizations_policy.dec_s3_baseline.id
  target_id = local.org_root_id
}

# -----------------------------------------------------------------------------
# AI services opt-out policy
#
# Not an authorization control - a management policy that sets an org-wide
# default: AWS AI/ML services may not store our content or use it to
# develop/improve AWS and affiliate models. services.default covers every AI
# service, including future ones; @@none on the child-policy operators
# prevents member accounts or child OUs from relaxing it. Inherited by all
# current and future accounts.
# -----------------------------------------------------------------------------

resource "aws_organizations_policy" "ai_opt_out" {
  name        = "${var.rsc_name}-ai-services-opt-out"
  description = "Opt every account out of AWS using our content to improve its AI/ML services."
  type        = "AISERVICES_OPT_OUT_POLICY"

  content = jsonencode({
    services = {
      default = {
        "@@operators_allowed_for_child_policies" = ["@@none"]
        opt_out_policy = {
          "@@operators_allowed_for_child_policies" = ["@@none"]
          "@@assign"                               = "optOut"
        }
      }
    }
  })
}

resource "aws_organizations_policy_attachment" "ai_opt_out_root" {
  policy_id = aws_organizations_policy.ai_opt_out.id
  target_id = local.org_root_id
}
