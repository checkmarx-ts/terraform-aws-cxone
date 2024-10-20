module "rds-analytics" {
  source  = "terraform-aws-modules/rds-aurora/aws"
  version = "9.9.0"
  create  = var.db_create

  name                                        = "${var.deployment_id}-analytics"
  engine                                      = "aurora-postgresql"
  engine_version                              = var.db_engine_version
  allow_major_version_upgrade                 = var.db_allow_major_version_upgrade
  engine_mode                                 = "provisioned"
  instance_class                              = var.analytics_db_instance_class
  vpc_id                                      = var.vpc_id
  kms_key_id                                  = var.kms_key_arn
  db_subnet_group_name                        = aws_db_subnet_group.main.name
  storage_encrypted                           = true
  apply_immediately                           = var.db_apply_immediately
  skip_final_snapshot                         = var.db_skip_final_snapshot
  final_snapshot_identifier                   = var.analytics_db_final_snapshot_identifier
  auto_minor_version_upgrade                  = var.db_auto_minor_version_upgrade
  iam_database_authentication_enabled         = false
  snapshot_identifier                         = var.analytics_db_snapshot_identifer
  monitoring_interval                         = var.db_monitoring_interval
  performance_insights_enabled                = var.db_performance_insights_enabled
  performance_insights_retention_period       = var.db_performance_insights_retention_period
  db_cluster_db_instance_parameter_group_name = var.analytics_db_cluster_db_instance_parameter_group_name
  master_username                             = "analytics"
  database_name                               = "analytics"
  master_password                             = var.analytics_db_master_user_password
  manage_master_user_password                 = false
  port                                        = var.db_port
  deletion_protection                         = var.db_deletion_protection
  backup_retention_period                     = var.db_backup_retention_period
  enabled_cloudwatch_logs_exports             = ["postgresql"]
  security_group_rules = {
    ingress_from_vpc = {
      cidr_blocks = data.aws_vpc.main.cidr_block_associations[*].cidr_block
    }
  }
  serverlessv2_scaling_configuration = var.analytics_db_instance_class == "db.serverless" ? var.analytics_db_serverlessv2_scaling_configuration : {}
  instances                          = var.analytics_db_instances
}


module "rds-proxy-analytics" {
  source  = "terraform-aws-modules/rds-proxy/aws"
  version = "3.1.0"
  create  = var.db_create && var.db_create_rds_proxy

  name                   = var.deployment_id
  vpc_subnet_ids         = var.db_subnets
  vpc_security_group_ids = [module.rds_proxy_sg.security_group_id]
  endpoints = {
    read_write = {
      name                   = "read-write-endpoint"
      vpc_subnet_ids         = var.db_subnets
      vpc_security_group_ids = [module.rds_proxy_sg.security_group_id]
    },
    read_only = {
      name                   = "read-only-endpoint"
      vpc_subnet_ids         = var.db_subnets
      vpc_security_group_ids = [module.rds_proxy_sg.security_group_id]
      target_role            = "READ_ONLY"
    }
  }

  auth = {
    "root" = {
      description = "Cluster generated master user password"
      secret_arn  = var.db_create ? (var.analytics_db_master_user_password == null ? module.rds-analytics.cluster_master_user_secret[0].secret_arn : var.analytics_db_master_user_password) : null
      auth_sceme  = "SECRETS"
      iam_auth    = "DISABLED"
    }
  }

  engine_family = "POSTGRESQL"
  debug_logging = true

  # Target Aurora cluster
  target_db_cluster     = true
  db_cluster_identifier = module.rds-analytics.cluster_id

}


output "analytics_db_endpoint" {
  value = var.db_create_rds_proxy ? module.rds-proxy-analytics.db_proxy_endpoints.read_write.endpoint : module.rds-analytics.cluster_endpoint
}

output "analytics_db_port" {
  value = module.rds-analytics.cluster_port
}

output "analytics_db_reader_endpoint" {
  value = var.db_create_rds_proxy ? module.rds-proxy-analytics.db_proxy_endpoints.read_only.endpoint : module.rds-analytics.cluster_reader_endpoint
}

output "analytics_db_database_name" {
  value = module.rds-analytics.cluster_database_name
}

output "analytics_db_master_username" {
  value = module.rds-analytics.cluster_master_username
}

output "analytics_db_master_password" {
  value     = module.rds-analytics.cluster_master_password
  sensitive = true
}