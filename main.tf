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

  vpc_cidr    = module.vpc.vpc_cidr_block
  internal    = module.security_groups.internal
  external    = module.security_groups.external
  rds         = module.security_groups.rds
  elasticache = module.security_groups.elasticache
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
    ast_tenant_name        = var.ast_tenant_name
    aws_region             = data.aws_region.current.name
    admin_password         = var.cxone_admin_password
    admin_email            = var.cxone_admin_email
    domain                 = "${var.subdomain}${var.domain}"
    acm_arn                = module.acm.acm_certificate_arn

        

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

    #  SMTP
    smtp_host        = var.SMTP_endpoint
    smtp_port        = var.SMTP_port
    smtp_user        = module.ses.access_key_id
    smtp_password    = module.ses.ses_smtp_password
    smtp_from_sender = var.SMTP_from_sender



  })
  filename = "${path.module}/kots.${var.deployment_id}.yml"
}

resource "local_file" "install_sh" {
  content = templatefile("./install.sh.tftpl", {
    kots_config_file = "kots.${var.deployment_id}.yml"
  })
  filename = "${path.module}/install.${var.deployment_id}.sh"
}

data "aws_route53_zone" "hosted_zone" {
  name = var.domain
  private_zone = false
}

module "acm" {
  source  = "terraform-aws-modules/acm/aws"
  version = "5.0.0"

  domain_name  = "${var.subdomain}${var.domain}"
  zone_id      = data.aws_route53_zone.hosted_zone.zone_id

  validation_method = "DNS"
  create_certificate = true
  create_route53_records = true
  validate_certificate = true
  wait_for_validation = true

  tags = {
    Name = var.deployment_id
  }
}


module "ses" {
  source            = "cloudposse/ses/aws"
  version           = "0.24.0"
  zone_id           = data.aws_route53_zone.hosted_zone.zone_id
  domain            = "${var.subdomain}${var.domain}"
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
  name  = "cxone_ses_group_policy"
  group = module.ses.ses_group_name

  policy = jsonencode ({
    Version: "2012-10-17"
    Statement: [
        {
            Effect: "Allow",
            Action: [
                "ses:SendEmail",
                "ses:SendRawEmail"
            ],
            Resource: "*"
        }
    ]
  })
}


##
### Fluentbit Logging Resources Below
##

data "aws_eks_cluster" "eks" {
  name = var.deployment_id
  depends_on = [module.eks_cluster.cluster_certificate_authority_data]
}

data "aws_caller_identity" "current" {}

resource "kubernetes_namespace" "logs" {
  metadata {
    name = "logs"
  }
}

resource "aws_iam_policy" "fluentbit" {
  name_prefix = "${var.deployment_id}-${var.environment}-fluentbit-policy"
  description = "IAM policy for fluentbit"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid = "fluentBitLogManagement"
        Action = [
          "logs:PutLogEvents",
          "logs:Describe*",
          "logs:CreateLogStream",
          "logs:CreateLogGroup",
          "logs:PutRetentionPolicy"
        ]
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role" "fluentbit-role" {
  name_prefix        = "fluentbit"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/${replace(data.aws_eks_cluster.eks.identity.0.oidc.0.issuer, "https://", "")}"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringLike": {
          "${replace(data.aws_eks_cluster.eks.identity.0.oidc.0.issuer, "https://", "")}:sub": "system:serviceaccount:logs:fluentbit-sa"
        }
      }
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "fluentbit" {
  policy_arn = aws_iam_policy.fluentbit.arn
  role       = aws_iam_role.fluentbit-role.name
}


resource "kubernetes_service_account" "fluentbit" {
  metadata {
    name      = "fluentbit-sa"
    namespace = kubernetes_namespace.logs.id
    annotations = {
      "eks.amazonaws.com/role-arn" = "${aws_iam_role.fluentbit-role.arn}"
    }
  }

  automount_service_account_token = true
}

##
### AWS fluentbit helm chart below
##
resource "helm_release" "fluent-bit-cloudwatch" {
  repository = "https://aws.github.io/eks-charts"
  chart      = "aws-for-fluent-bit" 
  name       = "cloudwatch"
  namespace  = kubernetes_namespace.logs.id

  values = [
    templatefile("./aws-fluentbit-config.yml", {
      region        = data.aws_region.current.name
      deployment_id = var.deployment_id
    })
  ] 
}
