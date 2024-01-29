module "vpc" {
  source        = "./modules/vpc"
  deployment_id = var.deployment_id
  vpc_cidr      = var.vpc_cidr
}

module "security_groups" {
  source        = "./modules/security-groups"
  deployment_id = var.deployment_id
  vpc_id        = module.vpc.vpc_id
  vpc_cidr      = module.vpc.vpc_cidr_block
}

# The security groups module will configure the required VPC Internal rules only. It will not allow EKS node egress to the internet. 
# This egress rule is added below in the project so that it can be customized.
# Access to the internet is required for online installations (image pulling), and some application features (e.g. integration with other tools) require internet connectivity as well.
resource "aws_security_group_rule" "node_egress_all" {
  description       = "All protocols"
  type              = "egress"
  from_port         = -1
  to_port           = -1
  protocol          = "all"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = module.security_groups.eks_node
}


# Allow image pulls from checkmarx.jfrog.io. For use by Checkmarx internal labs or in rare cases when images are pulled directly from Checkmarx's Artifactory.
# Most images are pulled from the replicated proxy, which has rules below. 
# Reference https://jfrog.com/help/r/what-are-artifactory-cloud-nated-ips
resource "aws_security_group_rule" "checkmarx_jfrog_io" {
  description       = "Allow image pulls from checkmarx.jfrog.io"
  type              = "egress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["54.73.4.50/32", "34.246.139.145/32", "34.247.22.236/32"]
  security_group_id = module.security_groups.eks_node
}

# Replicated services - required for online installation.
# Reference https://docs.replicated.com/enterprise/installing-general-requirements
resource "aws_security_group_rule" "replicated_services" {
  description       = "Allow image pulls from proxy.replicated.com and replicated api"
  type              = "egress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["162.159.137.43/32", "162.159.138.43/32", "162.159.133.41/32", "162.159.134.41/32"]
  security_group_id = module.security_groups.eks_node
}

# SCA API - required for SCA Scanning.
# Reference https://checkmarx.com/resource/documents/en/34965-19103-connectivity-to-checkmarx-sca-cloud.html
resource "aws_security_group_rule" "sca_us_environment" {
  description       = "Allow connection to sca-api.checkmarx.net (US Environment)"
  type              = "egress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["3.163.101.20/32", "3.163.101.86/32", "3.163.101.52/32", "3.163.101.98/32"]
  security_group_id = module.security_groups.eks_node
}

resource "aws_security_group_rule" "sca_eu_environment" {
  description       = "Allow connection to sca-api.checkmarx.net (EU Environment)"
  type              = "egress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["3.161.163.9/32", "3.161.163.101/32", "3.161.163.106/32", "3.161.163.94/32"]
  security_group_id = module.security_groups.eks_node
}

resource "aws_security_group_rule" "codebashing_api" {
  description       = "Allow connection to api.codebashing.com"
  type              = "egress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["54.246.53.245/32", "108.128.155.15/32", "54.77.213.21/32"]
  security_group_id = module.security_groups.eks_node
}





module "kms" {
  source = "./modules/kms"
}

module "iam" {
  source = "./modules/iam"

  deployment_id              = var.deployment_id
  administrator_iam_role_arn = var.administrator_iam_role_arn
}


module "s3" {
  source        = "./modules/s3"
  deployment_id = var.deployment_id
}


module "eks_cluster" {
  source = "./modules/eks-cluster"

  deployment_id               = var.deployment_id
  vpc_id                      = module.vpc.vpc_id
  subnet_ids                  = module.vpc.private_subnets
  eks_kms_key_arn             = module.kms.eks_kms_key_arn
  cluster_access_iam_role_arn = module.iam.cluster_access_iam_role_arn
  cluster_security_group_id   = module.security_groups.eks_cluster
  node_security_group_id      = module.security_groups.eks_node
  s3_bucket_name_suffix       = module.s3.s3_bucket_name_suffix

}


resource "random_password" "rds_password" {
  length           = 16
  special          = false
  override_special = "!*-_[]{}<>"
  min_special      = 0
  min_upper        = 1
  min_lower        = 1
  min_numeric      = 1
}

module "rds" {
  source = "./modules/rds"

  deployment_id        = var.deployment_id
  vpc_id               = module.vpc.vpc_id
  db_subnet_group_name = module.vpc.database_subnet_group_name
  security_group_ids   = [module.security_groups.rds]
  database_name        = "ast"
  database_password    = local.db_password
  database_username    = "ast"
  kms_key_arn          = module.kms.eks_kms_key_arn
}


module "elasticache" {
  source = "./modules/elasticache"

  deployment_id      = var.deployment_id
  kms_key_arn        = module.kms.eks_kms_key_arn
  security_group_ids = [module.security_groups.elasticache]
  subnet_ids         = module.vpc.private_subnets
}

module "opensearch" {
  source             = "./modules/opensearch"
  deployment_id      = var.deployment_id
  subnet_ids         = [module.vpc.private_subnets[0], module.vpc.private_subnets[1]]
  security_group_ids = [module.security_groups.opensearch]
  password           = local.db_password

}

module "acm" {
  source = "./modules/acm"

  domain        = var.domain
  subdomain     = var.subdomain
  deployment_id = var.deployment_id
}

module "ses" {
  source = "./modules/ses"

  domain        = var.domain
  subdomain     = var.subdomain
  deployment_id = var.deployment_id
}

data "aws_region" "current" {}

resource "local_file" "kots_config" {
  content = templatefile("./kots.config.tftpl", {
    ast_tenant_name     = var.ast_tenant_name
    aws_region          = data.aws_region.current.name
    admin_password      = var.cxone_admin_password
    admin_email         = var.cxone_admin_email
    domain              = "${var.subdomain}${var.domain}"
    acm_certificate_arn = module.acm.acm_certificate_arn



    # S3 buckets
    engine_logs_bucket          = module.s3.engine_logs_bucket_id
    imports_bucket              = module.s3.imports_bucket_id
    kics_worker_bucket          = module.s3.kics_worker_bucket_id
    logs_bucket                 = module.s3.logs_bucket_id
    misc_bucket                 = module.s3.misc_bucket_id
    apisec_bucket               = module.s3.api_security_bucket_id
    audit_bucket                = module.s3.audit_bucket_id
    configuration_bucket        = module.s3.configuration_bucket_id
    queries_bucket              = module.s3.queries_bucket_id
    report_templates_bucket     = module.s3.report_templates_bucket_id
    reports_bucket              = module.s3.reports_bucket_id
    repostore_bucket            = module.s3.repostore_bucket_id
    sast_metadata_bucket        = module.s3.sast_metadata_bucket_id
    sast_worker_bucket          = module.s3.sast_worker_bucket_id
    sca_worker_bucket           = module.s3.sca_worker_bucket_id
    scans_bucket                = module.s3.scans_bucket_id
    source_resolver_bucket      = module.s3.source_resolver_bucket_id
    uploads_bucket              = module.s3.uploads_bucket_id
    redis_shared_bucket         = module.s3.redis_bucket_id
    scan_results_storage_bucket = module.s3.scan_results_storage_bucket_id
    export_bucket               = module.s3.export_bucket_id
    cxone_bucket                = module.s3.cxone_bucket_id

    # RDS
    rds_endpoint               = module.rds.cluster_endpoint
    external_postgres_user     = module.rds.cluster_master_username
    external_postgres_password = local.db_password
    external_postgres_db       = module.rds.cluster_database_name


    # Redis
    external_redis_address = module.elasticache.redis_private_endpoint

    #  SMTP
    smtp_host        = var.SMTP_endpoint
    smtp_port        = var.SMTP_port
    smtp_user        = module.ses.access_key_id
    smtp_password    = module.ses.ses_smtp_password
    smtp_from_sender = var.SMTP_from_sender

    # Elasticsearch
    elasticsearch_host     = module.opensearch.endpoint
    elasticsearch_password = local.db_password


  })
  filename = "${path.module}/kots.${var.deployment_id}.yml"
}

resource "local_file" "install_sh" {
  content = templatefile("./install.sh.tftpl", {
    kots_config_file = "kots.${var.deployment_id}.yml"
  })
  filename = "${path.module}/install.${var.deployment_id}.sh"
}


