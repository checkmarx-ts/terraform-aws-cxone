
data "aws_partition" "current" {}
data "aws_region" "current" {}

resource "aws_eks_access_entry" "node" {

  cluster_name  = module.eks.cluster_name
  principal_arn = var.nodegroup_iam_role_arn
  type          = "EC2_LINUX"
}

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "20.28.0"

  cluster_name    = var.deployment_id
  cluster_version = var.eks_cluster_version

  cluster_enabled_log_types = ["audit", "api", "authenticator", "scheduler"]

  cluster_endpoint_private_access = var.enable_private_endpoint
  cluster_endpoint_public_access  = var.enable_public_endpoint

  vpc_id     = var.vpc_id
  subnet_ids = var.subnet_ids

  create_cluster_security_group = false
  cluster_security_group_id     = var.cluster_security_group_id

  create_node_security_group = false
  node_security_group_id     = var.node_security_group_id

  enable_irsa = true

  authentication_mode = "API"

  enable_cluster_creator_admin_permissions = true

  access_entries = {
    administrator = {
      principal_arn = var.cluster_access_iam_role_arn
      policy_associations = {
        admin = {
          policy_arn = "arn:${data.aws_partition.current.partition}:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
          access_scope = {
            type = "cluster"
          }
        }
      }
    }
  }


  cluster_addons = {
    coredns = {
      addon_version = var.coredns_version
    }
    kube-proxy = {
      addon_version = var.kube_proxy_version
    }
    vpc-cni = {
      addon_version  = var.vpc_cni_version
      before_compute = var.pod_custom_networking_subnets != null ? true : false
      configuration_values = jsonencode({
        env = {
          AWS_VPC_K8S_CNI_CUSTOM_NETWORK_CFG = var.pod_custom_networking_subnets != null ? "true" : "false"
          ENI_CONFIG_LABEL_DEF               = var.pod_custom_networking_subnets != null ? "topology.kubernetes.io/zone" : ""
      } })

    }
    aws-ebs-csi-driver = {
      addon_version            = var.aws_ebs_csi_driver_version
      service_account_role_arn = var.eks_create_ebs_csi_irsa ? module.ebs_csi_irsa[0].iam_role_arn : null
    }
  }


  create_kms_key = false
  cluster_encryption_config = {
    "resources"      = ["secrets"]
    provider_key_arn = var.eks_kms_key_arn
  }


  self_managed_node_group_defaults = {
    launch_template_version     = "$Latest"
    create_launch_template      = false
    use_name_prefix             = false
    iam_role_use_name_prefix    = false
    create_iam_instance_profile = false
    create_access_entry         = false
    iam_role_arn                = var.nodegroup_iam_role_arn
    cluster_name                = var.deployment_id
    cluster_version             = var.eks_cluster_version
    subnet_ids                  = var.subnet_ids
    create_iam_role             = false
  }

  self_managed_node_groups = { for node_group in var.self_managed_node_groups : node_group.name => {
    name                   = "${var.deployment_id}-${node_group.name}"
    launch_template_id     = node_group.launch_template_id
    min_size               = node_group.min_size
    max_size               = node_group.max_size
    desired_size           = node_group.desired_size
    labels                 = node_group.labels
    taints                 = node_group.taints
    autoscaling_group_tags = node_group.autoscaling_group_tags
    tags = {
      Name = "${var.deployment_id}-${node_group.name}"
    }
    lifecycle = {
      ignore_changes = ["desired_capacity"]
    }
  } }

}

module "ebs_csi_irsa" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "5.48.0"
  count   = var.eks_create_ebs_csi_irsa ? 1 : 0

  role_name             = "ebs-csi-${var.deployment_id}"
  role_description      = "IRSA role for EBS CSI Driver"
  attach_ebs_csi_policy = true
  ebs_csi_kms_cmk_ids   = [var.eks_kms_key_arn]
  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:ebs-csi-controller-sa"]
    }
  }
}


module "cluster_autoscaler_irsa" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "5.48.0"
  count   = var.eks_create_cluster_autoscaler_irsa ? 1 : 0

  role_name                        = "cluster-autoscaler-${var.deployment_id}"
  role_description                 = "IRSA role for cluster autoscaler"
  attach_cluster_autoscaler_policy = true

  cluster_autoscaler_cluster_names = [module.eks.cluster_name]
  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:cluster-autoscaler"]
    }
  }
}


module "external_dns_irsa" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "5.48.0"
  count   = var.eks_create_external_dns_irsa ? 1 : 0

  role_name        = "external-dns-${var.deployment_id}"
  role_description = "IRSA role for cluster external dns controller"
  #external_dns_hosted_zone_arns = var.external_dns_hosted_zone_arns
  # setting to false because we don't want to rely on exeternal policies
  attach_external_dns_policy = true
  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:external-dns"]
    }
  }
}


module "load_balancer_controller_irsa" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "5.48.0"
  count   = var.eks_create_load_balancer_controller_irsa ? 1 : 0

  role_name                              = "load_balancer_controller-${var.deployment_id}"
  role_description                       = "IRSA role for cluster load balancer controller"
  attach_load_balancer_controller_policy = true
  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:aws-load-balancer-controller"]
    }
  }
}

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    # kubectl = {
    #   source  = "gavinbunney/kubectl"
    #   version = ">= 1.14.0"
    # }
  }
}