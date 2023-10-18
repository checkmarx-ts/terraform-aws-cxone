module "rds-aurora" {
  source  = "terraform-aws-modules/rds-aurora/aws"
  version = "8.5.0"

  name = "${var.deployment_id}-checkmarxone"

  engine         = "aurora-postgresql"
  engine_mode    = "provisioned"
  engine_version = var.engine_version

  vpc_id                 = var.vpc_id
  create_db_subnet_group = false
  db_subnet_group_name   = var.db_subnet_group_name
  vpc_security_group_ids = var.security_group_ids
  create_security_group  = false

  instance_class = var.postgres_nodes.instance_type
  instances = {
    1 = {
      instance_class      = var.postgres_nodes.instance_type
      publicly_accessible = false
    }
  }

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