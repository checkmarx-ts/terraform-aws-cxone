
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

  iam_role_arn    = var.cluster_iam_role_arn
  create_iam_role = false

  cluster_enabled_log_types              = var.cluster_enabled_log_types
  cloudwatch_log_group_retention_in_days = var.cloudwatch_log_group_retention_in_days


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
      pod_identity_association = {
        role_arn        = var.vpc_cni_role_arn
        service_account = "aws-node"
      }
      configuration_values = jsonencode({
        env = {
          AWS_VPC_K8S_CNI_CUSTOM_NETWORK_CFG = var.pod_custom_networking_subnets != null ? "true" : "false"
          ENI_CONFIG_LABEL_DEF               = var.pod_custom_networking_subnets != null ? "topology.kubernetes.io/zone" : ""
      } })

    }
    aws-ebs-csi-driver = {
      addon_version = var.aws_ebs_csi_driver_version
      pod_identity_association = {
        role_arn        = var.ebs_csi_role_arn
        service_account = "ebs-csi-controller-sa"
      }
    }
    eks-pod-identity-agent = {
      addon_version = var.aws_eks_pod_identity_agent_driver_version
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
    mixed_instances_policy = node_group.mixed_instances_policy
    tags = {
      Name = "${var.deployment_id}-${node_group.name}"
    }
    lifecycle = {
      ignore_changes = ["desired_capacity"]
    }
  } }

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