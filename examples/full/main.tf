data "aws_region" "current" {}
data "aws_partition" "current" {}
data "aws_caller_identity" "current" {}
data "aws_availability_zones" "available" {
  state = "available"
}


resource "aws_kms_key" "main" {
  description             = "KMS Key for the Checkmarx One deployment named ${var.deployment_id}"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  tags = {
    Name = var.deployment_id
  }
}


resource "random_password" "elasticsearch" {
  length           = 32
  special          = false
  override_special = "!*-_[]{}<>"
  min_special      = 1
  min_upper        = 1
  min_lower        = 1
  min_numeric      = 1
}

resource "random_password" "db" {
  length           = 32
  special          = false
  override_special = "!*-_[]{}<>"
  min_special      = 1
  min_upper        = 1
  min_lower        = 1
  min_numeric      = 1
}

resource "random_password" "kots_admin" {
  length           = 14
  special          = false
  override_special = "!*-_[]{}<>"
  min_special      = 1
  min_upper        = 1
  min_lower        = 1
  min_numeric      = 1
}

resource "random_password" "cxone_admin" {
  length           = 14
  special          = false
  override_special = "!*-_[]{}<>"
  min_special      = 1
  min_upper        = 1
  min_lower        = 1
  min_numeric      = 1
}




module "acm" {
  source  = "terraform-aws-modules/acm/aws"
  version = "5.0.1"

  domain_name = var.fqdn
  zone_id     = var.route_53_hosted_zone_id

  validation_method      = "DNS"
  create_certificate     = true
  create_route53_records = true
  validate_certificate   = true
  wait_for_validation    = true
}

module "ses" {
  source            = "cloudposse/ses/aws"
  version           = "0.24.0"
  zone_id           = var.route_53_hosted_zone_id
  domain            = var.fqdn
  verify_domain     = true
  verify_dkim       = true
  ses_group_enabled = true
  ses_group_name    = "${var.deployment_id}-ses-group"
  ses_user_enabled  = true
  name              = "CxOne-${var.deployment_id}"
  environment       = "dev"
  enabled           = true

  tags = {
    Name = var.deployment_id
  }
}

resource "aws_iam_group_policy" "cxone_ses_group_policy" {
  name  = "${var.deployment_id}-ses-group-policy"
  group = module.ses.ses_group_name

  depends_on = [module.ses]

  policy = jsonencode({
    Version : "2012-10-17"
    Statement : [
      {
        Effect : "Allow",
        Action : [
          "ses:SendEmail",
          "ses:SendRawEmail"
        ],
        Resource : "*"
      }
    ]
  })
}


module "checkmarx-one" {
  source = "../../"

  # General Configuration
  deployment_id      = var.deployment_id
  ec2_key_name       = var.ec2_key_name
  vpc_id             = module.vpc.vpc_id
  kms_key_arn        = aws_kms_key.main.arn
  s3_allowed_origins = [var.fqdn]

  # EKS Configuration
  eks_create                               = var.eks_create
  eks_subnets                              = module.vpc.private_subnets
  eks_create_cluster_autoscaler_irsa       = var.eks_create_cluster_autoscaler_irsa
  eks_create_external_dns_irsa             = var.eks_create_external_dns_irsa
  eks_create_load_balancer_controller_irsa = var.eks_create_load_balancer_controller_irsa
  eks_create_karpenter                     = var.eks_create_karpenter
  eks_version                              = var.eks_version
  coredns_version                          = var.coredns_version
  kube_proxy_version                       = var.kube_proxy_version
  vpc_cni_version                          = var.vpc_cni_version
  aws_ebs_csi_driver_version               = var.aws_ebs_csi_driver_version
  eks_private_endpoint_enabled             = var.eks_private_endpoint_enabled
  eks_public_endpoint_enabled              = var.eks_public_endpoint_enabled
  eks_cluster_endpoint_public_access_cidrs = var.eks_cluster_endpoint_public_access_cidrs
  enable_cluster_creator_admin_permissions = var.enable_cluster_creator_admin_permissions
  launch_template_tags                     = var.launch_template_tags

  # RDS Configuration
  db_subnets                     = module.vpc.private_subnets
  db_engine_version              = var.db_engine_version
  db_allow_major_version_upgrade = var.db_allow_major_version_upgrade
  db_auto_minor_version_upgrade  = var.db_auto_minor_version_upgrade
  db_apply_immediately           = var.db_apply_immediately
  db_deletion_protection         = var.db_deletion_protection
  db_snapshot_identifer          = var.db_snapshot_identifer
  db_skip_final_snapshot         = var.db_skip_final_snapshot
  db_final_snapshot_identifier   = var.db_final_snapshot_identifier
  db_instance_class              = var.db_instance_class
  db_monitoring_interval         = var.db_monitoring_interval
  # When enabling autoscaling, you may need to edit and save the autoscaling policy (no updates needed)
  # to work around the issue described here: https://github.com/terraform-aws-modules/terraform-aws-rds-aurora/issues/432
  db_autoscaling_enabled                      = var.db_autoscaling_enabled
  db_autoscaling_min_capacity                 = var.db_autoscaling_min_capacity
  db_autoscaling_max_capacity                 = var.db_autoscaling_max_capacity
  db_autoscaling_target_cpu                   = var.db_autoscaling_target_cpu
  db_autoscaling_scale_out_cooldown           = var.db_autoscaling_scale_out_cooldown
  db_autoscaling_scale_in_cooldown            = var.db_autoscaling_scale_in_cooldown
  db_port                                     = var.db_port
  db_master_user_password                     = random_password.db.result
  db_create_rds_proxy                         = var.db_create_rds_proxy
  db_create                                   = var.db_create
  db_performance_insights_enabled             = var.db_performance_insights_enabled
  db_performance_insights_retention_period    = var.db_performance_insights_retention_period
  db_cluster_db_instance_parameter_group_name = var.db_cluster_db_instance_parameter_group_name
  # Set individual instance properties. Reference https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/rds_cluster_instance
  db_instances                          = var.db_instances
  db_serverlessv2_scaling_configuration = var.db_serverlessv2_scaling_configuration

  # Elasticache Configuration
  ec_create                         = var.ec_create
  ec_subnets                        = module.vpc.private_subnets
  ec_enable_serverless              = var.ec_enable_serverless
  ec_serverless_max_storage         = var.ec_serverless_max_storage
  ec_serverless_max_ecpu_per_second = var.ec_serverless_max_ecpu_per_second
  ec_engine_version                 = var.ec_engine_version
  ec_parameter_group_name           = var.ec_parameter_group_name
  ec_automatic_failover_enabled     = var.ec_automatic_failover_enabled
  ec_multi_az_enabled               = var.ec_multi_az_enabled
  ec_node_type                      = var.ec_node_type          # Production: cache.r7g.xlarge, Dev/Test: cache.r7g.large, Demo: cache.t4g.micro	
  ec_number_of_shards               = var.ec_number_of_shards   # Production 3, Dev/Test: 1, Demo: 1
  ec_replicas_per_shard             = var.ec_replicas_per_shard # Production 2, Dev/Test: 1, Demo: 0
  ec_auto_minor_version_upgrade     = var.ec_auto_minor_version_upgrade

  # Elasticsearch Configuration
  es_create              = var.es_create
  es_subnets             = module.vpc.private_subnets
  es_instance_count      = var.es_instance_count
  es_instance_type       = var.es_instance_type
  es_volume_size         = var.es_volume_size
  es_tls_security_policy = var.es_tls_security_policy
  es_password            = random_password.elasticsearch.result
}


module "checkmarx-one-install" {
  source = "../../modules/cxone-install"

  cxone_version       = var.kots_cxone_version
  release_channel     = var.kots_release_channel
  license_file        = var.kots_license_file
  kots_admin_password = random_password.kots_admin.result

  deployment_id                         = var.deployment_id
  region                                = data.aws_region.current.name
  admin_email                           = var.kots_admin_email
  admin_password                        = random_password.cxone_admin.result
  fqdn                                  = var.fqdn
  acm_certificate_arn                   = module.acm.acm_certificate_arn
  bucket_suffix                         = module.checkmarx-one.s3_bucket_name_suffix
  object_storage_endpoint               = "s3.${data.aws_region.current.name}.amazonaws.com"
  object_storage_access_key             = var.object_storage_access_key
  object_storage_secret_key             = var.object_storage_secret_key
  postgres_host                         = module.checkmarx-one.db_endpoint
  postgres_database_name                = module.checkmarx-one.db_database_name
  postgres_user                         = module.checkmarx-one.db_master_username
  postgres_password                     = module.checkmarx-one.db_master_password
  redis_address                         = module.checkmarx-one.ec_endpoint
  smtp_host                             = "email-smtp.${data.aws_region.current.name}.amazonaws.com"
  smtp_port                             = var.smtp_port
  smtp_password                         = module.ses.ses_smtp_password
  smtp_user                             = module.ses.user_name
  smtp_from_sender                      = "noreply@${var.fqdn}"
  elasticsearch_host                    = module.checkmarx-one.es_endpoint
  elasticsearch_password                = random_password.elasticsearch.result
  cluster_autoscaler_iam_role_arn       = module.checkmarx-one.cluster_autoscaler_iam_role_arn
  load_balancer_controller_iam_role_arn = module.checkmarx-one.load_balancer_controller_iam_role_arn
  external_dns_iam_role_arn             = module.checkmarx-one.external_dns_iam_role_arn
}
