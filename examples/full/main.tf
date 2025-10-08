data "aws_region" "current" {}
data "aws_partition" "current" {}
data "aws_caller_identity" "current" {}
data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  # Add the fqdn to the firewall rules
  additional_suricata_rules = <<EOF
# CxOne must talk to itself when performing token exchange to validate the FQDN (cxiam makes the connection) and for CxIAM to function overall.
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"${var.fqdn}"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240401001; rev:1;)

${var.additional_suricata_rules}

EOF
}

module "vpc" {
  source                     = "../../modules/inspection-vpc"
  deployment_id              = var.deployment_id
  primary_cidr_block         = var.primary_cidr_block
  secondary_cidr_block       = var.secondary_cidr_block
  interface_vpc_endpoints    = var.interface_vpc_endpoints
  create_interface_endpoints = var.create_interface_endpoints
  create_s3_endpoint         = var.create_s3_endpoint
  enable_firewall            = var.enable_firewall
  stateful_default_actions   = var.stateful_default_actions
  suricata_rules             = var.suricata_rules
  include_sca_rules          = var.include_sca_rules
  additional_suricata_rules  = local.additional_suricata_rules
  create_managed_rule_groups = var.create_managed_rule_groups
  managed_rule_groups        = var.managed_rule_groups
}


resource "aws_kms_key" "main" {
  description             = "KMS Key for the Checkmarx One deployment named ${var.deployment_id}"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  policy                  = null # Set your policy per your organization's needs.
  tags = {
    Name = var.deployment_id
  }
}


resource "random_password" "elasticsearch" {
  length           = 32
  special          = false
  override_special = var.password_override_special
  min_special      = 1
  min_upper        = 1
  min_lower        = 1
  min_numeric      = 1
}

resource "random_password" "db" {
  length           = 32
  special          = false
  override_special = var.password_override_special
  min_special      = 1
  min_upper        = 1
  min_lower        = 1
  min_numeric      = 1
}

resource "random_password" "analytics_db" {
  length           = 32
  special          = false
  override_special = var.password_override_special
  min_special      = 1
  min_upper        = 1
  min_lower        = 1
  min_numeric      = 1
}

resource "random_password" "kots_admin" {
  length           = 14
  special          = false
  override_special = var.password_override_special
  min_special      = 1
  min_upper        = 1
  min_lower        = 1
  min_numeric      = 1
}

resource "random_password" "cxone_admin" {
  length           = 14
  special          = false
  override_special = var.password_override_special
  min_special      = 1
  min_upper        = 1
  min_lower        = 1
  min_numeric      = 1
}

resource "random_password" "redis_auth" {
  length           = 16
  special          = false
  override_special = var.password_override_special
  min_special      = 1
  min_upper        = 1
  min_lower        = 1
  min_numeric      = 1
}

module "acm" {
  source  = "terraform-aws-modules/acm/aws"
  version = "5.0.1"
  count   = var.acm_certificate_arn != null ? 0 : 1

  domain_name = var.fqdn
  zone_id     = var.route_53_hosted_zone_id

  validation_method      = "DNS"
  create_certificate     = true
  create_route53_records = true
  validate_certificate   = true
  wait_for_validation    = true
}


locals {
  traefik_service_port          = 8443
  traefik_health_check_response = "404"
  alb_ingress_blocks            = ["0.0.0.0/0"]
  alb_egress_blocks             = ["0.0.0.0/0"]
}


resource "aws_security_group" "alb" {
  count       = var.create_alb == true ? 1 : 0
  name        = "${var.deployment_id}-alb"
  description = "Allow TLS inbound traffic"
  vpc_id      = module.vpc.vpc_id

  ingress {
    description = "TLS from Users"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = local.alb_ingress_blocks
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = local.alb_egress_blocks
  }

  tags = {
    Name = "${var.deployment_id}-alb"
  }
}


# ----------------------------------------------------------------------------------------------------------------------
# CREATE THE ALB
# ----------------------------------------------------------------------------------------------------------------------
resource "aws_lb" "lb" {
  count              = var.create_alb == true ? 1 : 0
  name               = "${var.deployment_id}-main"
  subnets            = module.vpc.public_subnets
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb[0].id]
  internal           = false

  # Preserve host header must be enabled for CxOne as traefik is listening for the host
  preserve_host_header = true

}

resource "aws_lb_target_group" "traefik_pods" {
  count       = var.create_alb == true ? 1 : 0
  name        = "${var.deployment_id}-traefik"
  port        = local.traefik_service_port
  protocol    = "HTTP"
  vpc_id      = module.vpc.vpc_id
  target_type = "ip"

  health_check {
    path                = "/"
    matcher             = "404"
    protocol            = "HTTP"
    healthy_threshold   = 5
    unhealthy_threshold = 2
  }
}

resource "aws_lb_listener" "https" {
  count             = var.create_alb == true ? 1 : 0
  load_balancer_arn = aws_lb.lb[0].arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-Res-2021-06"
  certificate_arn   = var.acm_certificate_arn != null ? var.acm_certificate_arn : module.acm[0].acm_certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.traefik_pods[0].arn
  }
}

# ----------------------------------------------------------------------------------------------------------------------
# CREATE THE DNS
# ----------------------------------------------------------------------------------------------------------------------
resource "aws_route53_record" "www" {
  count   = var.create_alb == true ? 1 : 0
  zone_id = var.route_53_hosted_zone_id
  name    = var.fqdn
  type    = "CNAME"
  ttl     = "300"
  records = [aws_lb.lb[0].dns_name]
}


output "alb_target_group_arn" {
  value = var.create_alb == true ? aws_lb_target_group.traefik_pods[0].arn : null
}

variable "create_alb" {
  default     = false
  type        = bool
  description = "Creates the externally managed ALB"
}


module "checkmarx-one" {
  source = "../../"

  # General Configuration
  deployment_id      = var.deployment_id
  ec2_key_name       = var.ec2_key_name
  vpc_id             = module.vpc.vpc_id
  vpc_private_cidrs  = module.vpc.vpc_cidr_blocks
  kms_key_arn        = aws_kms_key.main.arn
  s3_allowed_origins = [var.fqdn, "https://${var.fqdn}"]

  # EKS Configuration
  eks_create                               = var.eks_create
  eks_subnets                              = module.vpc.private_subnets
  create_node_s3_iam_role                  = var.create_node_s3_iam_role
  eks_pod_subnets                          = module.vpc.pod_subnets
  eks_enable_externalsnat                  = var.eks_enable_externalsnat
  eks_enable_fargate                       = var.eks_enable_fargate
  eks_create_cluster_autoscaler_irsa       = var.eks_create_cluster_autoscaler_irsa
  eks_create_external_dns_irsa             = var.eks_create_external_dns_irsa
  eks_create_load_balancer_controller_irsa = var.eks_create_load_balancer_controller_irsa
  eks_create_karpenter                     = var.eks_create_karpenter
  eks_ami_id                               = var.eks_ami_id
  eks_ami_type                             = var.eks_ami_type
  eks_ami_release_version                  = var.eks_ami_release_version
  eks_bootstrap_extra_args                 = var.eks_bootstrap_extra_args
  eks_enable_bootstrap_user_data           = var.eks_enable_bootstrap_user_data
  eks_pre_bootstrap_user_data              = var.eks_pre_bootstrap_user_data
  eks_post_bootstrap_user_data             = var.eks_post_bootstrap_user_data
  eks_cloudinit_pre_nodeadm                = var.eks_cloudinit_pre_nodeadm
  eks_cloudinit_post_nodeadm               = var.eks_cloudinit_post_nodeadm
  eks_cluster_security_group_additional_rules = {
    egress_nodes_ephemeral_ports_tcp = {
      description = "Ingress from VPC (management hosts)"
      protocol    = "tcp"
      from_port   = 443
      to_port     = 443
      type        = "ingress"
      cidr_blocks = module.vpc.vpc_cidr_blocks
    }
  }
  eks_version                              = var.eks_version
  coredns_version                          = var.coredns_version
  kube_proxy_version                       = var.kube_proxy_version
  vpc_cni_version                          = var.vpc_cni_version
  aws_ebs_csi_driver_version               = var.aws_ebs_csi_driver_version
  aws_cloudwatch_observability_version     = var.aws_cloudwatch_observability_version
  eks_private_endpoint_enabled             = var.eks_private_endpoint_enabled
  eks_public_endpoint_enabled              = var.eks_public_endpoint_enabled
  eks_cluster_endpoint_public_access_cidrs = var.eks_cluster_endpoint_public_access_cidrs
  enable_cluster_creator_admin_permissions = var.enable_cluster_creator_admin_permissions
  eks_administrator_principals             = var.eks_administrator_principals
  launch_template_tags                     = var.launch_template_tags
  eks_node_groups                          = var.eks_node_groups

  # RDS Configuration
  db_subnets                     = module.vpc.database_subnets
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
  db_master_user_password                     = var.password_override != null ? var.password_override : random_password.db.result
  db_create_rds_proxy                         = var.db_create_rds_proxy
  db_create                                   = var.db_create
  db_performance_insights_enabled             = var.db_performance_insights_enabled
  db_performance_insights_retention_period    = var.db_performance_insights_retention_period
  db_cluster_db_instance_parameter_group_name = var.db_cluster_db_instance_parameter_group_name
  # Set individual instance properties. Reference https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/rds_cluster_instance
  db_instances                          = var.db_instances
  db_serverlessv2_scaling_configuration = var.db_serverlessv2_scaling_configuration

  analytics_db_instance_class                           = var.analytics_db_instance_class
  analytics_db_final_snapshot_identifier                = var.analytics_db_final_snapshot_identifier
  analytics_db_snapshot_identifer                       = var.analytics_db_snapshot_identifer
  analytics_db_cluster_db_instance_parameter_group_name = var.analytics_db_cluster_db_instance_parameter_group_name
  analytics_db_instances                                = var.analytics_db_instances
  analytics_db_serverlessv2_scaling_configuration       = var.analytics_db_serverlessv2_scaling_configuration
  analytics_db_master_user_password                     = var.password_override != null ? var.password_override : random_password.analytics_db.result

  # Elasticache Configuration
  ec_create                         = var.ec_create
  ec_subnets                        = module.vpc.database_subnets
  ec_enable_serverless              = var.ec_enable_serverless
  ec_transit_encryption_enabled     = var.ec_transit_encryption_enabled
  ec_auth_token_strategy            = var.ec_auth_token_strategy
  ec_redis_auth_token               = var.ec_transit_encryption_enabled == true ? (var.password_override != null ? var.password_override : random_password.redis_auth.result) : ""
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
  es_create                        = var.es_create
  es_subnets                       = module.vpc.database_subnets
  es_enable_dedicated_master_nodes = var.es_enable_dedicated_master_nodes
  es_dedicated_master_count        = var.es_dedicated_master_count
  es_dedicated_master_type         = var.es_dedicated_master_type
  es_instance_count                = var.es_instance_count
  es_instance_type                 = var.es_instance_type
  es_volume_size                   = var.es_volume_size
  es_tls_security_policy           = var.es_tls_security_policy
  es_password                      = var.password_override != null ? var.password_override : random_password.elasticsearch.result
}


module "checkmarx-one-install" {
  source = "../../modules/cxone-install"

  cxone_version        = var.kots_cxone_version
  release_channel      = var.kots_release_channel
  license_file         = var.kots_license_file
  kots_admin_password  = var.password_override != null ? var.password_override : random_password.kots_admin.result
  kots_advanced_config = var.kots_advanced_config

  deployment_id                         = var.deployment_id
  cxone_namespace                       = var.cxone_namespace
  region                                = data.aws_region.current.region
  admin_email                           = var.kots_admin_email
  admin_password                        = var.password_override != null ? var.password_override : random_password.cxone_admin.result
  fqdn                                  = var.fqdn
  acm_certificate_arn                   = var.acm_certificate_arn != null ? var.acm_certificate_arn : module.acm[0].acm_certificate_arn
  bucket_suffix                         = module.checkmarx-one.s3_bucket_name_suffix
  ms_replica_count                      = var.ms_replica_count
  enable_keda_configuration             = var.enable_keda_configuration
  object_storage_endpoint               = "s3.${data.aws_region.current.region}.amazonaws.com"
  object_storage_access_key             = var.object_storage_access_key
  object_storage_secret_key             = var.object_storage_secret_key
  postgres_host                         = module.checkmarx-one.db_endpoint
  postgres_read_host                    = module.checkmarx-one.db_reader_endpoint
  postgres_database_name                = module.checkmarx-one.db_database_name
  postgres_user                         = module.checkmarx-one.db_master_username
  postgres_password                     = module.checkmarx-one.db_master_password
  analytics_postgres_host               = module.checkmarx-one.analytics_db_endpoint
  analytics_postgres_read_host          = module.checkmarx-one.analytics_db_reader_endpoint
  analytics_postgres_database_name      = module.checkmarx-one.analytics_db_database_name
  analytics_postgres_user               = module.checkmarx-one.analytics_db_master_username
  analytics_postgres_password           = module.checkmarx-one.analytics_db_master_password
  redis_address                         = module.checkmarx-one.ec_endpoint
  redis_tls_enabled                     = var.ec_transit_encryption_enabled
  redis_auth_token                      = var.ec_transit_encryption_enabled == true ? (var.password_override != null ? var.password_override : random_password.redis_auth.result) : ""
  smtp_host                             = var.smtp_host
  smtp_port                             = var.smtp_port
  smtp_password                         = var.smtp_password
  smtp_user                             = var.smtp_user
  smtp_from_sender                      = var.smtp_from_sender
  elasticsearch_host                    = module.checkmarx-one.es_endpoint
  elasticsearch_password                = var.password_override != null ? var.password_override : random_password.elasticsearch.result
  cluster_autoscaler_iam_role_arn       = module.checkmarx-one.cluster_autoscaler_iam_role_arn
  load_balancer_controller_iam_role_arn = module.checkmarx-one.load_balancer_controller_iam_role_arn
  external_dns_iam_role_arn             = module.checkmarx-one.external_dns_iam_role_arn
  karpenter_iam_role_arn                = module.checkmarx-one.karpenter_iam_role_arn
  cluster_endpoint                      = module.checkmarx-one.cluster_endpoint
  nodegroup_iam_role_name               = module.checkmarx-one.nodegroup_iam_role_name
  availability_zones                    = module.vpc.azs
  pod_eniconfig                         = module.vpc.ENIConfig
  vpc_id                                = module.vpc.vpc_id
  kms_key_arn                           = aws_kms_key.main.arn
  internal_ca_cert                      = var.internal_ca_cert
  network_load_balancer_scheme          = var.network_load_balancer_scheme
  airgap_bundle_path                    = var.airgap_bundle_path
  kots_registry                         = var.kots_registry
  kots_registry_username                = var.kots_registry_username
  kots_registry_password                = var.kots_registry_password
  target_group_arn                      = var.create_alb == true ? aws_lb_target_group.traefik_pods[0].arn : ""
}

output "cxone1" {
  value = module.checkmarx-one.eks
}
