data "aws_region" "current" {}
data "aws_partition" "current" {}

locals {
  spot_instance_groups = {
    # Repostore is special group since we only need slightly over 16Gb memory.
    repostore = ["c5n.2xlarge", "m5.2xlarge", "m5a.2xlarge", "m5ad.2xlarge", "m5d.2xlarge", "m5dn.2xlarge", "m5n.2xlarge", "m5zn.2xlarge", "m6a.2xlarge", "m6i.2xlarge", "m6id.2xlarge", "m6idn.2xlarge", "m6in.2xlarge", "m7a.2xlarge", "m7i-flex.2xlarge", "m7i.2xlarge"]
    # Zeebe special case needs 2x8
    zeebe = ["m7a.large", "m5zn.large", "m6a.large", "m6i.large", "m7i.large"]
    # small = 4x8 for kics
    small = ["c5.xlarge", "c5a.xlarge", "c5ad.xlarge", "c5d.xlarge", "c6a.xlarge", "c6i.xlarge", "c6id.xlarge", "c6in.xlarge", "c7a.xlarge", "c7i-flex.xlarge", "c7i.xlarge", "inf1.xlarge"]
    # medium = 8x32
    medium = ["m5.2xlarge", "m5a.2xlarge", "m5ad.2xlarge", "m5d.2xlarge", "m5dn.2xlarge", "m5n.2xlarge", "m5zn.2xlarge", "m6a.2xlarge", "m6i.2xlarge", "m6id.2xlarge", "m6idn.2xlarge", "m6in.2xlarge", "m7a.2xlarge", "m7i-flex.2xlarge", "m7i.2xlarge", "m5zn.3xlarge"]
    # large = 16x64
    large = ["m5.4xlarge", "m5a.4xlarge", "m5ad.4xlarge", "m5d.4xlarge", "m5dn.4xlarge", "m5n.4xlarge", "m6a.4xlarge", "m6i.4xlarge", "m6id.4xlarge", "m6idn.4xlarge", "m6in.4xlarge", "m7a.4xlarge", "m7i-flex.4xlarge", "m7i.4xlarge", "m5zn.6xlarge"]
    # xlarge = 32x128
    xlarge = ["m5.8xlarge", "m5a.8xlarge", "m5ad.8xlarge", "m5d.8xlarge", "m5dn.8xlarge", "m5n.8xlarge", "m6a.8xlarge", "m6i.8xlarge", "m6id.8xlarge", "m6idn.8xlarge", "m6in.8xlarge", "m7a.8xlarge", "m7i-flex.8xlarge", "m7i.8xlarge"]
    # xxlarge = 48x192
    xxlarge = ["m5.12xlarge", "m5a.12xlarge", "m5ad.12xlarge", "m5d.12xlarge", "m5dn.12xlarge", "m5n.12xlarge", "m5zn.12xlarge", "m6a.12xlarge", "m6i.12xlarge", "m6id.12xlarge", "m6idn.12xlarge", "m6in.12xlarge", "m7a.12xlarge", "m7i-flex.12xlarge", "m7i.12xlarge"]
  }
}

#Use this version of the VPC module to deploy a VPC without firewall
# module "vpc" {
#   source        = "./modules/vpc"
#   deployment_id = var.deployment_id
#   vpc_cidr      = var.vpc_cidr
# }

#This version of the VPC module uses AWS Network Firewall to provide egress filtering of the CxOne deployment.
module "vpc" {
  source = "./modules/vpc-with-firewall"

  deployment_id      = var.deployment_id
  primary_vpc_cidr   = var.vpc_cidr
  maximum_azs        = 3
  secondary_vpc_cidr = var.secondary_vpc_cidr
}



module "vpc_endpoints" {
  source = "./modules/vpc-endpoints"

  deployment_id      = var.deployment_id
  vpc_id             = module.vpc.vpc_id
  subnets            = module.vpc.private_subnets
  security_group_ids = [module.security_groups.vpc_endpoints]
  create_s3_endpoint = true
}




module "bastion" {
  source = "./modules/bastion-host"

  deployment_id           = var.deployment_id
  subnet_id               = module.vpc.private_subnets[0]
  key_name                = var.ec2_key_name            # The EC2 keypair name to access the server with
  remote_management_cidrs = var.remote_management_cidrs # Enter your IP address here, if you will use this server.
}


module "security_groups" {
  source             = "./modules/security-groups"
  deployment_id      = var.deployment_id
  vpc_id             = module.vpc.vpc_id
  vpc_cidr           = module.vpc.vpc_cidr_block
  secondary_vpc_cidr = var.secondary_vpc_cidr
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

  eks_kms_key_arn               = module.kms.eks_kms_key_arn
  eks_cluster_name              = module.eks_cluster.cluster_name
  external_dns_hosted_zone_arns = var.external_dns_hosted_zone_arns

  cluster_access_role_arn           = null
  node_role_arn                     = null
  cluster_role_arn                  = null
  cluster_autoscaler_role_arn       = null
  load_balancer_controller_role_arn = null
  create_external_dns_pod_identity  = true
  external_dns_role_arn             = null
  ebs_csi_role_arn                  = null
  vpc_cni_role_arn                  = null
}


module "s3" {
  source             = "./modules/s3"
  deployment_id      = var.deployment_id
  s3_allowed_origins = ["https://${var.subdomain}${var.domain}"]

  #-------------------------------------------
  # New policy controls - (default = true)
  #-------------------------------------------
  control_object_ownership              = true
  block_public_acls                     = true
  block_public_policy                   = true
  attach_public_policy                  = true
  ignore_public_acls                    = true
  restrict_public_buckets               = true
  attach_deny_insecure_transport_policy = true
}


module "eks_cluster" {
  source = "./modules/eks-cluster"

  deployment_id               = var.deployment_id
  vpc_id                      = module.vpc.vpc_id
  subnet_ids                  = module.vpc.public_subnets
  eks_kms_key_arn             = module.kms.eks_kms_key_arn
  cluster_access_iam_role_arn = module.iam.cluster_access_iam_role_arn
  cluster_security_group_id   = module.security_groups.eks_cluster
  node_security_group_id      = module.security_groups.eks_node
  nodegroup_iam_role_arn      = module.iam.eks_nodes_iam_role_arn
  cluster_iam_role_arn        = module.iam.eks_cluster_iam_role_arn
  ec2_key_name                = var.ec2_key_name
  ebs_csi_role_arn            = module.iam.ebs_csi_role_arn
  vpc_cni_role_arn            = module.iam.vpc_cni_role_arn

  self_managed_node_groups = [
    {
      name               = "ast-app2"
      min_size           = 3
      desired_size       = 3
      max_size           = 15
      launch_template_id = aws_launch_template.self_managed["ast-app"].id
      autoscaling_group_tags = {
        "k8s.io/cluster-autoscaler/enabled"                     = true
        "k8s.io/cluster-autoscaler/${var.deployment_id}"        = "owned"
        "k8s.io/cluster-autoscaler/node-template/label/ast-app" = "true"
      }
      # mixed_instances_policy = {
      #   instances_distribution = {
      #     on_demand_base_capacity                  = 0
      #     on_demand_percentage_above_base_capacity = 25
      #     spot_allocation_strategy                 = "capacity-optimized"
      #   }
      #   launch_template = {
      #     launch_template_specification = {
      #       launch_template_id = aws_launch_template.self_managed["ast-app"].id
      #     }
      #     override = {
      #       instance_type     = "t3.2xlarge"
      #       weighted_capacity = "1"
      #     }
      #     override = {
      #       instance_type     = "t3a.2xlarge"
      #       weighted_capacity = "1"
      #     }
      #   }
      # }
    },
    {
      name               = "sast-engine"
      min_size           = 0
      desired_size       = 0
      max_size           = 100
      launch_template_id = aws_launch_template.self_managed["sast-engine"].id
      autoscaling_group_tags = {
        "k8s.io/cluster-autoscaler/enabled"                         = "true"
        "k8s.io/cluster-autoscaler/${var.deployment_id}"            = "owned"
        "k8s.io/cluster-autoscaler/node-template/label/sast-engine" = "true"
        "k8s.io/cluster-autoscaler/node-template/taint/sast-engine" = "true:NO_SCHEDULE"
      }
      labels = {
        "sast-engine" = "true"
      }
      taints = {
        dedicated = {
          key    = "sast-engine"
          value  = "true"
          effect = "NO_SCHEDULE"
        }
      }
    },
    {
      name               = "sast-engine-large"
      min_size           = 0
      desired_size       = 0
      max_size           = 100
      launch_template_id = aws_launch_template.self_managed["sast-engine-large"].id
      autoscaling_group_tags = {
        "k8s.io/cluster-autoscaler/enabled"                               = "true"
        "k8s.io/cluster-autoscaler/${var.deployment_id}"                  = "owned"
        "k8s.io/cluster-autoscaler/node-template/label/sast-engine-large" = "true"
        "k8s.io/cluster-autoscaler/node-template/taint/sast-engine-large" = "true:NO_SCHEDULE"
      }
      labels = {
        "sast-engine-large" = "true"
      }
      taints = {
        dedicated = {
          key    = "sast-engine-large"
          value  = "true"
          effect = "NO_SCHEDULE"
        }
      }
    },
    {
      name               = "sast-engine-extra-large"
      min_size           = 0
      desired_size       = 0
      max_size           = 100
      launch_template_id = aws_launch_template.self_managed["sast-engine-extra-large"].id
      autoscaling_group_tags = {
        "k8s.io/cluster-autoscaler/enabled"                                     = "true"
        "k8s.io/cluster-autoscaler/${var.deployment_id}"                        = "owned"
        "k8s.io/cluster-autoscaler/node-template/label/sast-engine-extra-large" = "true"
        "k8s.io/cluster-autoscaler/node-template/taint/sast-engine-extra-large" = "true:NO_SCHEDULE"
      }
      labels = {
        "sast-engine-extra-large" = "true"
      }
      taints = {
        dedicated = {
          key    = "sast-engine-extra-large"
          value  = "true"
          effect = "NO_SCHEDULE"
        }
      }
    },
    {
      name               = "sast-engine-xxl"
      min_size           = 0
      desired_size       = 0
      max_size           = 100
      launch_template_id = aws_launch_template.self_managed["sast-engine-xxl"].id
      autoscaling_group_tags = {
        "k8s.io/cluster-autoscaler/enabled"                             = "true"
        "k8s.io/cluster-autoscaler/${var.deployment_id}"                = "owned"
        "k8s.io/cluster-autoscaler/node-template/label/sast-engine-xxl" = "true"
        "k8s.io/cluster-autoscaler/node-template/taint/sast-engine-xxl" = "true:NO_SCHEDULE"
      }
      labels = {
        "sast-engine-xxl" = "true"
      }
      taints = {
        dedicated = {
          key    = "sast-engine-xxl"
          value  = "true"
          effect = "NO_SCHEDULE"
        }
      }
    },
    {
      name               = "kics-engine"
      min_size           = 0
      desired_size       = 0
      max_size           = 100
      launch_template_id = aws_launch_template.self_managed["kics-engine"].id
      autoscaling_group_tags = {
        "k8s.io/cluster-autoscaler/enabled"                         = "true"
        "k8s.io/cluster-autoscaler/${var.deployment_id}"            = "owned"
        "k8s.io/cluster-autoscaler/node-template/label/kics-engine" = "true"
        "k8s.io/cluster-autoscaler/node-template/taint/kics-engine" = "true:NO_SCHEDULE"
      }
      labels = {
        "kics-engine" = "true"
      }
      taints = {
        dedicated = {
          key    = "kics-engine"
          value  = "true"
          effect = "NO_SCHEDULE"
        }
      }
    },
    {
      name               = "repostore"
      min_size           = 1
      desired_size       = 1
      max_size           = 15
      launch_template_id = aws_launch_template.self_managed["repostore"].id
      autoscaling_group_tags = {
        "k8s.io/cluster-autoscaler/enabled"                       = "true"
        "k8s.io/cluster-autoscaler/${var.deployment_id}"          = "owned"
        "k8s.io/cluster-autoscaler/node-template/label/repostore" = "true"
        "k8s.io/cluster-autoscaler/node-template/taint/repostore" = "true:NO_SCHEDULE"
      }
      labels = {
        "repostore" = "true"
      }
      taints = {
        dedicated = {
          key    = "repostore"
          value  = "true"
          effect = "NO_SCHEDULE"
        }
      }
    },
    {
      name               = "sca-source-resolver"
      min_size           = 1
      desired_size       = 1
      max_size           = 15
      launch_template_id = aws_launch_template.self_managed["sca-source-resolver"].id
      autoscaling_group_tags = {
        "k8s.io/cluster-autoscaler/enabled"                     = "true"
        "k8s.io/cluster-autoscaler/${var.deployment_id}"        = "owned"
        "k8s.io/cluster-autoscaler/node-template/label/service" = "sca-source-resolver"
        "k8s.io/cluster-autoscaler/node-template/taint/service" = "sca-source-resolver:NO_SCHEDULE"
      }
      labels = {
        "service" = "sca-source-resolver"
      }
      taints = {
        dedicated = {
          key    = "service"
          value  = "sca-source-resolver"
          effect = "NO_SCHEDULE"
        }
      }
    }
  ]
}


resource "random_password" "rds_password" {
  length           = 32
  special          = false
  override_special = "!*-_"
  min_special      = 1
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

  # Monitoring can be enabled by setting a non zero value for cluster_monitoring_interval and provided an IAM role.
  monitoring_role_arn         = module.iam.rds_role_arn
  cluster_monitoring_interval = 60
  # Monitoring is disabled with this config:
  # monitoring_role_arn         = null
  # cluster_monitoring_interval = 0
}

module "rds-analytics" {
  source = "./modules/rds"

  deployment_id        = "${var.deployment_id}-analytics"
  vpc_id               = module.vpc.vpc_id
  db_subnet_group_name = module.vpc.database_subnet_group_name
  security_group_ids   = [module.security_groups.rds]
  database_name        = "analytics"
  database_password    = random_password.rds_password.result
  database_username    = "analytics"
  kms_key_arn          = module.kms.eks_kms_key_arn
}


module "elasticache" {
  source = "./modules/elasticache"

  deployment_id      = var.deployment_id
  kms_key_arn        = module.kms.eks_kms_key_arn
  security_group_ids = [module.security_groups.elasticache]
  subnet_ids         = module.vpc.private_subnets
}


resource "random_password" "opensearch_password" {
  # The master user password must contain at least one uppercase letter, one lowercase letter, one number, and one special character.
  length           = 32
  special          = false
  override_special = "!*-_[]{}<>"
  min_special      = 1
  min_upper        = 1
  min_lower        = 1
  min_numeric      = 1
}


module "opensearch" {
  source             = "./modules/opensearch"
  deployment_id      = var.deployment_id
  subnet_ids         = [module.vpc.private_subnets[0], module.vpc.private_subnets[1]]
  security_group_ids = [module.security_groups.opensearch]
  password           = random_password.opensearch_password.result
}

module "acm" {
  source = "./modules/acm"

  domain        = var.domain
  subdomain     = var.subdomain
  deployment_id = var.deployment_id
}


resource "random_password" "kotsadm_password" {
  length           = 14
  special          = false
  override_special = "!*-_[]{}<>"
  min_special      = 1
  min_upper        = 1
  min_lower        = 1
  min_numeric      = 1
}


module "checkmarx-one-install" {
  source = "git::https://github.com/checkmarx-ts/terraform-aws-cxone//modules/cxone-install?ref=8a1736d"

  airgap_bundle_path     = var.airgap_bundle_path
  kots_registry          = var.kots_registry
  kots_registry_username = var.kots_registry_username
  kots_registry_password = var.kots_registry_password

  cxone_version       = var.cxone_version
  release_channel     = var.cxone_release_channel
  license_file        = var.license_file
  kots_admin_password = random_password.kotsadm_password.result

  deployment_id             = var.deployment_id
  region                    = data.aws_region.current.region
  admin_email               = var.cxone_admin_email
  admin_password            = var.cxone_admin_password
  fqdn                      = "${var.subdomain}${var.domain}"
  acm_certificate_arn       = module.acm.acm_certificate_arn
  bucket_suffix             = module.s3.s3_bucket_name_suffix
  ms_replica_count          = "1"
  object_storage_endpoint   = "s3.${data.aws_region.current.region}.amazonaws.com"
  object_storage_access_key = var.object_storage_access_key
  object_storage_secret_key = var.object_storage_secret_key
  postgres_host             = module.rds.cluster_endpoint
  #postgres_read_host                    = module.rds.cluster_reader_endpoint
  postgres_database_name  = module.rds.cluster_database_name
  postgres_user           = module.rds.cluster_master_username
  postgres_password       = random_password.rds_password.result
  analytics_postgres_host = module.rds-analytics.cluster_endpoint
  #analytics_postgres_read_host          = module.rds-analytics.cluster_reader_endpoint
  analytics_postgres_database_name      = module.rds-analytics.cluster_database_name
  analytics_postgres_user               = module.rds-analytics.cluster_master_username
  analytics_postgres_password           = random_password.rds_password.result
  redis_address                         = module.elasticache.redis_private_endpoint
  smtp_host                             = var.SMTP_endpoint
  smtp_port                             = var.SMTP_port
  smtp_password                         = var.SMTP_password
  smtp_user                             = var.SMTP_user
  smtp_from_sender                      = var.SMTP_from_sender
  elasticsearch_host                    = module.opensearch.endpoint                 #"{{ elasticsearch_host }}"     #
  elasticsearch_password                = random_password.opensearch_password.result # "{{ elasticsearch_password }}" 
  cluster_autoscaler_iam_role_arn       = module.iam.cluster_autoscaler_role_arn
  load_balancer_controller_iam_role_arn = module.iam.load_balancer_controller_role_arn
  external_dns_iam_role_arn             = module.iam.external_dns_role_arn
  karpenter_iam_role_arn                = "adsf"
  cluster_endpoint                      = module.eks_cluster.cluster_endpoint
  nodegroup_iam_role_name               = module.iam.eks_nodes_iam_role_name
  availability_zones                    = module.vpc.azs #["us-west-2a", "us-west-2b"]
  pod_eniconfig                         = "null"
  vpc_id                                = module.vpc.vpc_id
  kms_key_arn                           = module.kms.eks_kms_key_arn
}

