data "aws_region" "current" {}

# Use this version of the VPC module to deploy a VPC without firewall
# module "vpc" {
#   source        = "./modules/vpc"
#   deployment_id = var.deployment_id
#   vpc_cidr      = var.vpc_cidr
# }

# This version of the VPC module uses AWS Network Firewall to provide egress filtering of the CxOne deployment.
module "vpc" {
  source = "./modules/vpc-with-firewall"

  deployment_id = var.deployment_id
  vpc_cidr      = var.vpc_cidr
  maximum_azs   = 2
}


module "vpc_endpoints" {
  source = "./modules/vpc-endpoints"

  deployment_id      = var.deployment_id
  vpc_id             = module.vpc.vpc_id
  subnets            = module.vpc.private_subnets
  security_group_ids = [module.security_groups.vpc_endpoints]
}



# module "bastion" {
#   source = "./modules/bastion-host"

#   deployment_id           = var.deployment_id
#   subnet_id               = module.vpc.private_subnets[0]
#   key_name                = "fdo"                # The EC2 keypair name to access the server with
#   remote_management_cidrs = ["45.30.164.210/32"] # Enter your IP address here, if you will use this server.
# }



module "security_groups" {
  source        = "./modules/security-groups"
  deployment_id = var.deployment_id
  vpc_id        = module.vpc.vpc_id
  vpc_cidr      = module.vpc.vpc_cidr_block
}



# The security groups module will configure the required VPC Internal rules only. It will not allow EKS node egress to the internet. 
# This egress rule is added below in the project so that it can be customized.
# Access to the internet is required for online installations (image pulling), and some application features (e.g. integration with other tools, AWS API access) require internet connectivity
resource "aws_security_group_rule" "node_egress_all" {
  description       = "All protocols"
  type              = "egress"
  from_port         = -1
  to_port           = -1
  protocol          = "all"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = module.security_groups.eks_node
}

module "kms" {
  source = "./modules/kms"
}

module "iam" {
  source = "./modules/iam"

  deployment_id              = var.deployment_id
  administrator_iam_role_arn = var.administrator_iam_role_arn
  s3_bucket_name_suffix      = module.s3.s3_bucket_name_suffix
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
  nodegroup_iam_role_arn      = module.iam.eks_nodes_iam_role_arn
}

module "karpenter" {
  source = "./modules/karpenter"

  deployment_id               = var.deployment_id
  vpc_id                      = module.vpc.vpc_id
  subnet_ids                  = module.vpc.private_subnets
  eks_kms_key_arn             = module.kms.eks_kms_key_arn
  cluster_access_iam_role_arn = module.iam.cluster_access_iam_role_arn
  cluster_security_group_id   = module.security_groups.eks_cluster
  node_security_group_id      = module.security_groups.eks_node
  nodegroup_iam_role_arn      = module.iam.eks_nodes_iam_role_arn
  nodegroup_iam_role_name     = module.iam.eks_nodes_iam_role_name
}

module "cluster-externaldns" {
  source = "./modules/cluster-externaldns"

  deployment_id     = var.deployment_id
  oidc_provider_arn = module.eks_cluster.oidc_provider_arn
}

module "cluster-loadbalancer" {
  source = "./modules/cluster-loadbalancer"

  deployment_id     = var.deployment_id
  oidc_provider_arn = module.eks_cluster.oidc_provider_arn
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
  database_password    = random_password.rds_password.result
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
  password           = random_password.rds_password.result
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
