resource "aws_rds_cluster_parameter_group" "main" {
  name        = "${var.deployment_id}-main-cluster"
  family      = "aurora-postgresql13"
  description = "RDS cluster parameter group for ${var.deployment_id}"

  parameter {
    name  = "log_autovacuum_min_duration"
    value = "1000"
  }

  parameter {
    name  = "rds.force_autovacuum_logging_level"
    value = "log"
  }
  parameter {
    name  = "password_encryption"
    value = "scram-sha-256"
  }
}

resource "aws_db_parameter_group" "main" {
  name   = "${var.deployment_id}-main-instance"
  family = "aurora-postgresql13"

  parameter {
    name  = "auto_explain.log_min_duration"
    value = "500"
  }

  parameter {
    name  = "log_connections"
    value = "1"
  }
  parameter {
    name  = "log_disconnections"
    value = "1"
  }
  parameter {
    name  = "log_lock_waits"
    value = "1"
  }
  parameter {
    name  = "log_min_duration_statement"
    value = "100"
  }
  parameter {
    name  = "log_min_error_statement"
    value = "warning"
  }
  parameter {
    name  = "log_statement"
    value = "ddl"
  }
}

module "rds" {
  source  = "terraform-aws-modules/rds-aurora/aws"
  version = "9.15.0"
  create  = var.db_create

  name                                  = "${var.deployment_id}-main"
  engine                                = "aurora-postgresql"
  engine_version                        = var.db_engine_version
  allow_major_version_upgrade           = var.db_allow_major_version_upgrade
  engine_mode                           = "provisioned"
  instance_class                        = var.db_instance_class
  autoscaling_enabled                   = var.db_autoscaling_enabled
  autoscaling_min_capacity              = var.db_autoscaling_min_capacity
  autoscaling_max_capacity              = var.db_autoscaling_max_capacity
  autoscaling_target_cpu                = var.db_autoscaling_target_cpu
  autoscaling_scale_in_cooldown         = var.db_autoscaling_scale_in_cooldown
  autoscaling_scale_out_cooldown        = var.db_autoscaling_scale_out_cooldown
  vpc_id                                = var.vpc_id
  kms_key_id                            = var.kms_key_arn
  db_subnet_group_name                  = aws_db_subnet_group.main.name
  storage_encrypted                     = true
  apply_immediately                     = var.db_apply_immediately
  skip_final_snapshot                   = var.db_skip_final_snapshot
  final_snapshot_identifier             = var.db_final_snapshot_identifier
  auto_minor_version_upgrade            = var.db_auto_minor_version_upgrade
  iam_database_authentication_enabled   = false
  snapshot_identifier                   = var.db_snapshot_identifer
  monitoring_interval                   = var.db_monitoring_interval
  performance_insights_enabled          = var.db_performance_insights_enabled
  performance_insights_retention_period = var.db_performance_insights_retention_period
  db_cluster_parameter_group_name       = aws_rds_cluster_parameter_group.main.name
  db_parameter_group_name               = aws_db_parameter_group.main.name
  master_username                       = "ast"
  database_name                         = "ast"
  master_password                       = var.db_master_user_password
  manage_master_user_password           = false
  port                                  = var.db_port
  deletion_protection                   = var.db_deletion_protection
  backup_retention_period               = var.db_backup_retention_period
  enabled_cloudwatch_logs_exports       = ["postgresql"]
  security_group_rules = {
    ingress_from_vpc = {
      cidr_blocks = var.vpc_private_cidrs
    }
  }
  serverlessv2_scaling_configuration = var.db_instance_class == "db.serverless" ? var.db_serverlessv2_scaling_configuration : {}
  instances                          = var.db_instances
}




resource "aws_db_subnet_group" "main" {
  name       = "${var.deployment_id}-rds"
  subnet_ids = var.db_subnets

  tags = {
    Name = "${var.deployment_id}"
  }
}


module "rds-proxy" {
  source  = "terraform-aws-modules/rds-proxy/aws"
  version = "3.2.1"
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
      secret_arn  = var.db_create ? (var.db_master_user_password == null ? module.rds.cluster_master_user_secret[0].secret_arn : var.db_master_user_password) : null
      auth_sceme  = "SECRETS"
      iam_auth    = "DISABLED"
    }
  }

  engine_family = "POSTGRESQL"
  debug_logging = true

  # Target Aurora cluster
  target_db_cluster     = true
  db_cluster_identifier = module.rds.cluster_id

}

module "rds_proxy_sg" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "5.1.2"
  create  = var.db_create && var.db_create_rds_proxy

  name        = "${var.deployment_id}-proxy"
  description = "PostgreSQL RDS Proxy security group"
  vpc_id      = var.vpc_id

  revoke_rules_on_delete = true

  ingress_with_cidr_blocks = [
    {
      description = "Private subnet PostgreSQL access"
      rule        = "postgresql-tcp"
      cidr_blocks = data.aws_vpc.main.cidr_block
    }
  ]

  egress_with_cidr_blocks = [
    {
      description = "Database subnet PostgreSQL access"
      rule        = "postgresql-tcp"
      cidr_blocks = data.aws_vpc.main.cidr_block
    },
  ]
}

output "db_endpoint" {
  value = var.db_create_rds_proxy ? module.rds-proxy.db_proxy_endpoints.read_write.endpoint : module.rds.cluster_endpoint
}

output "db_port" {
  value = module.rds.cluster_port
}

output "db_reader_endpoint" {
  value = var.db_create_rds_proxy ? module.rds-proxy.db_proxy_endpoints.read_only.endpoint : module.rds.cluster_reader_endpoint
}

output "db_database_name" {
  value = module.rds.cluster_database_name
}

output "db_master_username" {
  value = module.rds.cluster_master_username
}

output "db_master_password" {
  value     = module.rds.cluster_master_password
  sensitive = true
}