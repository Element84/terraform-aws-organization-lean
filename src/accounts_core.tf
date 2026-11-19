# -----------------------------------------------------------------------------
# Core accounts: Log_Archive, Audit, Shared_Services
#
# The accounts at the core of the landing zone. Changing them should be very
# rare. An AWS account's root email address must be unique, hence the plus
# addressing.
# -----------------------------------------------------------------------------

module "acct_log_archive" {
  source = "./modules/account"

  name      = "Log_Archive"
  email     = "${var.base_email.user}+log-archive-acct@${var.base_email.domain}"
  parent_id = aws_organizations_organizational_unit.security.id

  # These should almost always be the same for every account. They are
  # inputs only to allow for variance later.
  role_name      = local.org_access_role
  opt_in_regions = local.opt_in_regions
  contacts       = var.contacts

  # depends_on is required on every call to the account module: the module's
  # contact and region resources reach into the member account via the Account
  # Management API, which works only once trusted access is enabled.
  depends_on = [aws_organizations_aws_service_access.account_management]
}

module "acct_audit" {
  source = "./modules/account"

  name           = "Audit"
  email          = "${var.base_email.user}+audit-acct@${var.base_email.domain}"
  parent_id      = aws_organizations_organizational_unit.security.id
  role_name      = local.org_access_role
  contacts       = var.contacts
  opt_in_regions = local.opt_in_regions

  depends_on = [aws_organizations_aws_service_access.account_management]
}

module "acct_shared_services" {
  source = "./modules/account"

  name           = "Shared_Services"
  email          = "${var.base_email.user}+sharedserv-acct@${var.base_email.domain}"
  parent_id      = aws_organizations_organizational_unit.infrastructure.id
  role_name      = local.org_access_role
  contacts       = var.contacts
  opt_in_regions = local.opt_in_regions

  depends_on = [aws_organizations_aws_service_access.account_management]
}
