module "rds-aurora" {
  source  = "terraform-aws-modules/rds-aurora/aws"
  version = "9.13.0"

  name = "${var.deployment_id}-checkmarxone-${var.database_name}"

  engine         = "aurora-postgresql"
  engine_mode    = "provisioned"
  engine_version = var.engine_version

  create_monitoring_role      = false
  monitoring_role_arn         = var.monitoring_role_arn
  cluster_monitoring_interval = var.cluster_monitoring_interval

  create_cloudwatch_log_group            = var.create_cloudwatch_log_group
  cloudwatch_log_group_retention_in_days = var.cloudwatch_log_group_retention_in_days
  enabled_cloudwatch_logs_exports        = var.enabled_cloudwatch_logs_exports
  cloudwatch_log_group_skip_destroy      = var.cloudwatch_log_group_skip_destroy
  cloudwatch_log_group_kms_key_id        = var.cloudwatch_log_group_kms_key_id
  cloudwatch_log_group_class             = var.cloudwatch_log_group_class

  vpc_id                 = var.vpc_id
  create_db_subnet_group = false
  db_subnet_group_name   = var.db_subnet_group_name
  vpc_security_group_ids = var.security_group_ids
  create_security_group  = false
  copy_tags_to_snapshot  = true

  allow_major_version_upgrade                 = var.allow_major_version_upgrade
  db_cluster_parameter_group_name             = aws_rds_cluster_parameter_group.main.name
  db_parameter_group_name                     = aws_db_parameter_group.main.name
  db_cluster_db_instance_parameter_group_name = var.allow_major_version_upgrade ? aws_db_parameter_group.main.name : null

  instance_class                     = var.postgres_nodes.instance_type
  instances                          = var.db_instances
  serverlessv2_scaling_configuration = var.postgres_nodes.instance_type == "db.serverless" ? var.serverlessv2_scaling_configuration : {}


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

  snapshot_identifier = var.snapshot_identifier

  master_username             = var.database_username
  master_password             = var.database_password
  database_name               = var.database_name
  manage_master_user_password = false

}

locals {
  db_parameter_group_family = "aurora-postgresql${split(".", var.engine_version)[0]}"

  cluster_parameter_defaults = {
    log_autovacuum_min_duration          = { value = "1000", apply_method = "immediate" }
    "rds.force_autovacuum_logging_level" = { value = "log", apply_method = "immediate" }
    password_encryption                  = { value = "scram-sha-256", apply_method = "immediate" }
    max_connections                      = { value = "LEAST({DBInstanceClassMemory/9531392},5000)", apply_method = "pending-reboot" }
  }

  instance_parameter_defaults = {
    "auto_explain.log_min_duration" = { value = "500", apply_method = "immediate" }
    log_connections                 = { value = "1", apply_method = "immediate" }
    log_disconnections              = { value = "1", apply_method = "immediate" }
    log_lock_waits                  = { value = "1", apply_method = "immediate" }
    log_min_duration_statement      = { value = "100", apply_method = "immediate" }
    log_min_error_statement         = { value = "warning", apply_method = "immediate" }
    log_statement                   = { value = "ddl", apply_method = "immediate" }
  }
}

resource "aws_rds_cluster_parameter_group" "main" {
  name_prefix = "${var.deployment_id}-${var.database_name}-cluster-"
  family      = local.db_parameter_group_family
  description = "RDS cluster parameter group for ${var.deployment_id}"

  lifecycle {
    create_before_destroy = true
  }

  dynamic "parameter" {
    for_each = merge(local.cluster_parameter_defaults, var.cluster_parameter_overrides)
    content {
      name         = parameter.key
      value        = parameter.value.value
      apply_method = parameter.value.apply_method
    }
  }
}

resource "aws_db_parameter_group" "main" {
  name_prefix = "${var.deployment_id}-${var.database_name}-instance-"
  family      = local.db_parameter_group_family

  lifecycle {
    create_before_destroy = true
  }

  dynamic "parameter" {
    for_each = merge(local.instance_parameter_defaults, var.instance_parameter_overrides)
    content {
      name         = parameter.key
      value        = parameter.value.value
      apply_method = parameter.value.apply_method
    }
  }
}