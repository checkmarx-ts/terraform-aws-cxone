resource "helm_release" "analytics-rds-database-preparation" {

  depends_on = [
    module.rds,
    module.rds-analytics,
    module.eks
  ]

  name    = "database-preparation"
  chart   = "${path.module}/helm/database-preparation"
  version = "0.1.0"

  # Set the namespace to install the release into
  namespace        = "ast"
  create_namespace = true
  set {
    name  = "rds.analytics_enabled"
    value = "false"
  }

  set {
    name  = "rds.byor_enabled"
    value = "true"
  }

  set {
    name  = "rds.writer_endpoint"
    value = module.rds.cluster_endpoint
  }

  set {
    name  = "rds.masterUsername"
    value = "ast"
  }

  set {
    name  = "rds.masterPassword"
    value = var.db_master_user_password
  }

  set {
    name  = "rds.analytics_db_name"
    value = "analytics"
  }

  set {
    name  = "rds.byor_db_name"
    value = "byor"
  }

  # Wait for the release to be deployed
  wait = true
}