module "vpc" {
  source        = "./modules/vpc"
  deployment_id = var.deployment_id
  vpc_cidr      = var.vpc_cidr
}

module "security_groups" {
  source        = "./modules/security-groups"
  deployment_id = var.deployment_id
  vpc_id        = module.vpc.vpc_id
}

module "security_group_rules" {
  source = "./modules/security-group-rules"

  vpc_cidr = module.vpc.vpc_cidr_block
  internal = module.security_groups.internal
  external = module.security_groups.external
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
  default_security_group_ids  = [module.security_groups.internal]
  cluster_access_iam_role_arn = module.iam.cluster_access_iam_role_arn
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

data "aws_region" "current" {}

resource "local_file" "kots_config" {
  content = templatefile("./kots.config.tftpl", {
    ast_tenant_name = "elco_lab"
    aws_region      = data.aws_region.current.name

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

    # RDS
    rds_endpoint               = module.rds.cluster_endpoint
    external_postgres_user     = module.rds.cluster_master_username
    external_postgres_password = local.db_password
    external_postgres_db       = module.rds.cluster_database_name

    # Redis
    external_redis_address = module.elasticache.redis_private_endpoint

  })
  filename = "${path.module}/kots.${var.deployment_id}.yml"
}



resource "local_file" "install_sh" {
  content = templatefile("./install.sh.tftpl", {
    kots_config_file = "kots.${var.deployment_id}.yml"
  })
  filename = "${path.module}/install.${var.deployment_id}.sh"
}


