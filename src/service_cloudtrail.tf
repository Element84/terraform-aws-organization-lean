# -----------------------------------------------------------------------------
# CloudTrail

# The organization trail, created in the management account. It logs
# management events from every account and every enabled region (current
# and future, automatically) into an S3 bucket in the Log_Archive account.
#
# Management events only; paid data events are not enabled. Log file
# validation produces signed digests so tampering is detectable.
# -----------------------------------------------------------------------------

locals {
  cloudtrail_trail_name  = "${var.rsc_name}-org-trail"
  cloudtrail_bucket_name = "${var.rsc_name}-cloudtrail-logs-${module.acct_log_archive.account_id}"

  # Constructed as a string: the bucket policy needs the trail's ARN (as a
  # confused-deputy guard) before the trail exists, and the trail can't be
  # created until the bucket policy allows it to write - referencing the
  # trail resource here would be circular.
  cloudtrail_trail_arn = "arn:aws:cloudtrail:${var.home_region}:${aws_organizations_organization.this.master_account_id}:trail/${local.cloudtrail_trail_name}"
}

# Creating an organization trail through the API (unlike the console) does
# not enable trusted access. Same pattern as Access Analyzer.
resource "aws_organizations_aws_service_access" "cloudtrail" {
  service_principal = "cloudtrail.amazonaws.com"

  depends_on = [aws_organizations_organization.this]
}

# --- Log Bucket -------------------------------------------------------------

resource "aws_s3_bucket" "cloudtrail" {
  provider = aws.log_archive

  bucket              = local.cloudtrail_bucket_name
  object_lock_enabled = true

  lifecycle {
    # The org's audit history: never deletable via a casual terraform apply.
    prevent_destroy = true
  }

  depends_on = [module.acct_log_archive]
}

# Object Lock prerequisite. CloudTrail never overwrites an object, so
# versioning adds essentially no storage.
resource "aws_s3_bucket_versioning" "cloudtrail" {
  provider = aws.log_archive

  bucket = aws_s3_bucket.cloudtrail.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Immutability on our logs
resource "aws_s3_bucket_object_lock_configuration" "cloudtrail" {
  provider = aws.log_archive

  bucket = aws_s3_bucket.cloudtrail.id

  rule {
    default_retention {
      mode  = "GOVERNANCE"
      years = 3
    }
  }

  depends_on = [aws_s3_bucket_versioning.cloudtrail]
}

resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  provider = aws.log_archive

  bucket = aws_s3_bucket.cloudtrail.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# SSE-S3 is the S3 default. Declared explicitly because this bucket is so
# important.
resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail" {
  provider = aws.log_archive

  bucket = aws_s3_bucket.cloudtrail.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Recent logs stay hot for investigations, then step down in temperature.
# Deep Archive retrievals take hours - acceptable for logs over a year old.
resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail" {
  provider = aws.log_archive

  bucket = aws_s3_bucket.cloudtrail.id

  rule {
    id     = "log-retention"
    status = "Enabled"

    filter {}

    transition {
      days          = 90
      storage_class = "GLACIER_IR"
    }

    transition {
      days          = 365
      storage_class = "DEEP_ARCHIVE"
    }

    expiration {
      days = 1825 # 5 years
    }

    # The bucket is versioned, so expiration above only lays down a delete
    # marker; this purges the now-noncurrent version for real (its 30-day
    # object lock, counted from creation, lapsed years earlier).
    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }

  rule {
    id     = "housekeeping"
    status = "Enabled"

    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    # Once a delete marker's versions are purged, remove the marker too -
    # "deleted" then actually means gone.
    expiration {
      expired_object_delete_marker = true
    }
  }
}

# The standard CloudTrail delivery policy. Member-account logs land under
# AWSLogs/<org-id>/, the management account's own under AWSLogs/<account-id>/.
# aws:SourceArn pins delivery to our trail so no other account's CloudTrail
# can write here; the TLS-only deny is bucket-wide hygiene.
resource "aws_s3_bucket_policy" "cloudtrail" {
  provider = aws.log_archive

  bucket = aws_s3_bucket.cloudtrail.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.cloudtrail.arn
        Condition = {
          StringEquals = { "aws:SourceArn" = local.cloudtrail_trail_arn }
        }
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource = [
          "${aws_s3_bucket.cloudtrail.arn}/AWSLogs/${aws_organizations_organization.this.master_account_id}/*",
          "${aws_s3_bucket.cloudtrail.arn}/AWSLogs/${aws_organizations_organization.this.id}/*",
        ]
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"  = "bucket-owner-full-control"
            "aws:SourceArn" = local.cloudtrail_trail_arn
          }
        }
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.cloudtrail.arn,
          "${aws_s3_bucket.cloudtrail.arn}/*",
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      },
    ]
  })
}

# --- The Trail --------------------------------------------------------------

# CloudTrail validates it can write to the bucket at creation time, hence
# the hard dependency on the bucket policy.
resource "aws_cloudtrail" "org" {
  name           = local.cloudtrail_trail_name
  s3_bucket_name = aws_s3_bucket.cloudtrail.bucket

  is_organization_trail         = true
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true

  depends_on = [
    aws_s3_bucket_policy.cloudtrail,
    aws_organizations_aws_service_access.cloudtrail,
  ]
}
