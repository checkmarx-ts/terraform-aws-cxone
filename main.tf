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
  length      = 16
  special     = true
  min_special = 1
  min_upper   = 1
  min_lower   = 1
  min_numeric = 1
}

# module "rds" {
#   source = "./modules/rds"

#   deployment_id        = var.deployment_id
#   vpc_id               = module.vpc.vpc_id
#   db_subnet_group_name = module.vpc.database_subnet_group_name
#   security_group_ids   = [module.security_groups.rds]
#   database_name        = "ast"
#   database_password    = random_password.rds_password.result
#   database_username    = "ast"
#   kms_key_arn          = module.kms.eks_kms_key_arn
# }

# module "elasticache" {
#   source = "./modules/elasticache"

#   deployment_id      = var.deployment_id
#   kms_key_arn        = module.kms.eks_kms_key_arn
#   security_group_ids = [module.security_groups.elasticache]
#   subnet_ids         = module.vpc.private_subnets
# }
