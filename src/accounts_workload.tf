# -----------------------------------------------------------------------------
# Workload Accounts
#
# An example workload: dev and prod in the Workloads OU, a sandbox in the
# Sandbox OU. Repeat this pattern for each project or team.
# -----------------------------------------------------------------------------

module "acct_workload_dev" {
  source = "./modules/account"

  name      = "Workload_Dev"
  email     = "${var.base_email.user}+workload-dev-acct@${var.base_email.domain}"
  parent_id = aws_organizations_organizational_unit.workloads.id

  # These should almost always be the same for every account. They are
  # inputs only to allow for variance later.
  role_name      = local.org_access_role
  contacts       = var.contacts
  opt_in_regions = local.opt_in_regions

  # depends_on is required on every call to the account module: the module's
  # contact and region resources reach into the member account via the Account
  # Management API, which works only once trusted access is enabled.
  depends_on = [aws_organizations_aws_service_access.account_management]
}

module "acct_workload_prod" {
  source = "./modules/account"

  name           = "Workload_Prod"
  email          = "${var.base_email.user}+workload-prod-acct@${var.base_email.domain}"
  parent_id      = aws_organizations_organizational_unit.workloads.id
  role_name      = local.org_access_role
  contacts       = var.contacts
  opt_in_regions = local.opt_in_regions

  depends_on = [aws_organizations_aws_service_access.account_management]
}

module "acct_workload_sandbox" {
  source = "./modules/account"

  name           = "Workload_Sandbox"
  email          = "${var.base_email.user}+workload-sandbox-acct@${var.base_email.domain}"
  parent_id      = aws_organizations_organizational_unit.sandbox.id
  role_name      = local.org_access_role
  contacts       = var.contacts
  opt_in_regions = local.opt_in_regions

  depends_on = [aws_organizations_aws_service_access.account_management]
}
