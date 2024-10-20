# core_configuration_encryption_key is 64 character hex value
resource "random_password" "core_configuration_encryption_key" {
  count            = var.core_configuration_encryption_key == null ? 1 : 0
  length           = 64
  special          = true
  override_special = "abcdef0123456789"
  min_special      = 64
  min_upper        = 0
  min_lower        = 0
  min_numeric      = 0
}

resource "random_password" "sca_client_secret" {
  count       = var.sca_client_secret == null ? 1 : 0
  length      = 16
  special     = false
  min_special = 0
  min_upper   = 1
  min_lower   = 1
  min_numeric = 1
}

resource "random_password" "integration_encryption_key" {
  count       = var.integration_encryption_key == null ? 1 : 0
  length      = 24
  special     = false
  min_special = 0
  min_upper   = 1
  min_lower   = 1
  min_numeric = 1
}

resource "random_password" "integrations_repos_manager_azure_tenant_key" {
  count       = var.integrations_repos_manager_azure_tenant_key == null ? 1 : 0
  length      = 8
  special     = false
  min_special = 0
  min_upper   = 1
  min_lower   = 1
  min_numeric = 1
}
resource "random_password" "integrations_repos_manager_bitbucket_tenant_key" {
  count       = var.integrations_repos_manager_bitbucket_tenant_key == null ? 1 : 0
  length      = 8
  special     = false
  min_special = 0
  min_upper   = 1
  min_lower   = 1
  min_numeric = 1
}
resource "random_password" "integrations_repos_manager_github_tenant_key" {
  count       = var.integrations_repos_manager_github_tenant_key == null ? 1 : 0
  length      = 8
  special     = false
  min_special = 0
  min_upper   = 1
  min_lower   = 1
  min_numeric = 1
}
resource "random_password" "integrations_repos_manager_gitlab_tenant_key" {
  count       = var.integrations_repos_manager_gitlab_tenant_key == null ? 1 : 0
  length      = 8
  special     = false
  min_special = 0
  min_upper   = 1
  min_lower   = 1
  min_numeric = 1
}
