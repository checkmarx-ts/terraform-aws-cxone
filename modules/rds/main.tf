module "rds-aurora" {
  source  = "terraform-aws-modules/rds-aurora/aws"
  version = "9.10.0"

  name = "${var.deployment_id}-checkmarxone-${var.database_name}"

  engine         = "aurora-postgresql"
  engine_mode    = "provisioned"
  engine_version = var.engine_version

  vpc_id                 = var.vpc_id
  create_db_subnet_group = false
  db_subnet_group_name   = var.db_subnet_group_name
  vpc_security_group_ids = var.security_group_ids
  create_security_group  = false

  db_cluster_parameter_group_name = aws_rds_cluster_parameter_group.main.name
  db_parameter_group_name         = aws_db_parameter_group.main.name

  instance_class = var.postgres_nodes.instance_type
  instances      = var.db_instances


  autoscaling_enabled      = var.postgres_nodes.auto_scaling_enable
  autoscaling_min_capacity = var.postgres_nodes.count
  autoscaling_max_capacity = var.postgres_nodes.max_count

  storage_encrypted = true
  kms_key_id        = var.kms_key_arn

  apply_immediately                   = true
  skip_final_snapshot                 = true
  auto_minor_version_upgrade          = true
  performance_insights_enabled        = true
  iam_database_authentication_enabled = false

  master_username             = var.database_username
  master_password             = var.database_password
  database_name               = var.database_name
  manage_master_user_password = false

}

resource "aws_rds_cluster_parameter_group" "main" {
  name        = "${var.deployment_id}-${var.database_name}-cluster"
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
  name   = "${var.deployment_id}-${var.database_name}-instance"
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