module "rds-aurora" {
  source         = "terraform-aws-modules/rds-aurora/aws"
  version        = "6.1.4"
  create_cluster = var.postgres_nodes.create

  vpc_id                 = local.vpc_id
  create_db_subnet_group = false
  db_subnet_group_name   = local.db_subnet_group
  vpc_security_group_ids = [
    local.sig_k8s_to_dbs_id
  ]

  name = local.deployment_id

  engine         = "aurora-postgresql"
  engine_mode    = "provisioned"
  engine_version = "13.4"

  create_security_group = false
  allowed_cidr_blocks   = module.vpc.private_subnets_cidr_blocks

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
  kms_key_id        = local.kms_arn

  apply_immediately                   = true
  skip_final_snapshot                 = true
  auto_minor_version_upgrade          = true
  performance_insights_enabled        = true
  iam_database_authentication_enabled = false

  master_username = var.database_username
  master_password = var.database_password
  create_random_password = false
  database_name   = var.database_name

}