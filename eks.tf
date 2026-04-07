locals {
  eks_nodegroups = { for node_group in var.eks_node_groups : node_group.name => {
    name                 = "${var.deployment_id}-${node_group.name}"
    launch_template_name = "${var.deployment_id}-${node_group.name}"
    min_size             = node_group.min_size
    max_size             = node_group.max_size
    desired_size         = node_group.desired_size
    instance_types       = node_group.instance_types
    capacity_type        = node_group.capacity_type
    block_device_mappings = {
      xvda = {
        device_name = node_group.device_name
        ebs = {
          volume_size           = node_group.disk_size
          volume_type           = node_group.volume_type
          iops                  = node_group.disk_iops
          throughput            = node_group.disk_throughput
          encrypted             = true
          delete_on_termination = true
        }
      }
    }
    labels = node_group.labels
    taints = node_group.taints
    tags = {
      Name = "${var.deployment_id}-${node_group.name}"
    }
    lifecycle = {
      ignore_changes = ["desired_capacity"]
    }
    vpc_security_group_ids          = var.eks_node_additional_security_group_ids
    use_name_prefix                 = false
    iam_role_use_name_prefix        = false
    launch_template_use_name_prefix = false
    launch_template_tags            = var.launch_template_tags
    cluster_name                    = var.deployment_id
    cluster_version                 = var.eks_version
    subnet_ids                      = node_group.subnet_ids != null ? node_group.subnet_ids : var.eks_subnets
    timeouts                        = node_group.timeouts
    create_iam_role                 = false
    iam_role_arn                    = module.eks_node_iam_role.iam_role_arn
    key_name                        = var.ec2_key_name
    enable_bootstrap_user_data      = var.eks_enable_bootstrap_user_data
    post_bootstrap_user_data        = var.eks_post_bootstrap_user_data
    pre_bootstrap_user_data         = var.eks_pre_bootstrap_user_data
    cloudinit_pre_nodeadm           = var.eks_cloudinit_pre_nodeadm
    cloudinit_post_nodeadm          = var.eks_cloudinit_post_nodeadm
    ami_id                          = node_group.eks_ami_id != null ? node_group.eks_ami_id : var.eks_ami_id
    ami_type                        = node_group.eks_ami_type != null ? node_group.eks_ami_type : var.eks_ami_type
    ami_release_version             = node_group.eks_ami_release_version != null ? node_group.eks_ami_release_version : var.eks_ami_release_version
    bootstrap_extra_args            = var.eks_bootstrap_extra_args

    metadata_options = {
      http_endpoint               = "enabled"
      http_tokens                 = "required"
      instance_metadata_tags      = "disabled"
      http_put_response_hop_limit = "2"
    }
  } }

  admin_access_entries = { for entry in var.eks_administrator_principals : entry.name => {
    principal_arn = entry.principal_arn
    policy_associations = {
      admin = {
        policy_arn = "arn:${data.aws_partition.current.partition}:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
        access_scope = {
          type = "cluster"
        }
      }
    }
  } }

  # One ASG tag per taint entry so cluster-autoscaler node templates match nodes (taints map keys must be unique per group).
  cluster_autoscaler_nodegroup_taints = merge([
    for ng in var.eks_node_groups : {
      for taint_label, t in coalesce(ng.taints, {}) : "${ng.name}__${taint_label}" => {
        node_group_name = ng.name
        taint           = t
      }
    }
  ]...)
}

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "21.15.1" #"20.23.0" #
  create  = var.eks_create

  name               = var.deployment_id
  kubernetes_version = var.eks_version

  enabled_log_types = var.eks_enabled_log_types

  endpoint_private_access = var.eks_private_endpoint_enabled
  endpoint_public_access  = var.eks_public_endpoint_enabled

  vpc_id     = var.vpc_id
  subnet_ids = var.eks_subnets

  create_primary_security_group_tags = false
  create_security_group              = true
  #cluster_security_group_id     = var.cluster_security_group_id

  create_node_security_group = true
  #node_security_group_id     = module.eks_nodes_security_group.security_group_id

  node_security_group_additional_rules = {
    ingress_self_well_known = {
      description = "Node to node ingress on well known ports"
      protocol    = "tcp"
      from_port   = 1
      to_port     = 1024
      type        = "ingress"
      self        = true
    }

    ingress_alb = {
      description = "Allow ingress to traefik pods"
      protocol    = "tcp"
      from_port   = 8443
      to_port     = 8443
      type        = "ingress"
      cidr_blocks = var.vpc_private_cidrs
    }

  }

  enable_irsa = true

  enable_cluster_creator_admin_permissions = var.enable_cluster_creator_admin_permissions
  access_entries                           = local.admin_access_entries

  tags = {
    # NOTE - if creating multiple security groups with this module, only tag the
    # security group that Karpenter should utilize with the following tag
    # (i.e. - at most, only one security group should have this tag in your account)
    "karpenter.sh/discovery" = var.deployment_id
  }

  addons = {
    eks-pod-identity-agent = {
      addon_version  = var.aws_eks_pod_identity_agent_driver_version
      before_compute = true
    }
    coredns = {
      addon_version = var.coredns_version
    }
    kube-proxy = {
      addon_version = var.kube_proxy_version
    }
    vpc-cni = {
      addon_version  = var.vpc_cni_version
      before_compute = true
      pod_identity_association = [{
        role_arn        = module.vpc_cni_pod_identity.iam_role_arn
        service_account = "aws-node"
      }]
      configuration_values = jsonencode({
        env = {
          AWS_VPC_K8S_CNI_CUSTOM_NETWORK_CFG = tostring(var.eks_enable_custom_networking)
          ENI_CONFIG_LABEL_DEF               = var.eks_enable_custom_networking ? "topology.kubernetes.io/zone" : ""
          AWS_VPC_K8S_CNI_EXTERNALSNAT       = var.eks_enable_externalsnat ? "true" : "false"
        }
        # EniConfig = {
        #   create = false
        #   region = data.aws_region.current.name
        #   subnets = { for id in var.eks_pod_subnets : id => { id = id } }
        # }
      })
    }
    aws-ebs-csi-driver = {
      addon_version = var.aws_ebs_csi_driver_version
      pod_identity_association = [{
        role_arn        = module.ebs_csi_pod_identity.iam_role_arn
        service_account = "ebs-csi-controller-sa"
      }]
      configuration_values = jsonencode({
        controller = {
          extraVolumeTags = {
            "${var.cost_allocation_tag_key}" = var.cost_allocation_tag_value != "" ? var.cost_allocation_tag_value : var.deployment_id
          }
        }
      })
    }
  }
  create_kms_key = false
  encryption_config = {
    "resources"      = ["secrets"]
    provider_key_arn = var.kms_key_arn
  }


  security_group_additional_rules = var.eks_cluster_security_group_additional_rules
  eks_managed_node_groups         = local.eks_nodegroups

}

resource "aws_eks_addon" "amzn_cloudwatch_observability" {
  count                    = var.aws_cloudwatch_observability_version != null ? 1 : 0
  cluster_name             = module.eks.cluster_name
  addon_name               = "amazon-cloudwatch-observability"
  addon_version            = var.aws_cloudwatch_observability_version
  service_account_role_arn = module.aws_cloudwatch_observability_irsa[0].iam_role_arn
}


resource "aws_eks_addon" "metrics_server" {
  count         = var.metrics_server_version != null ? 1 : 0
  cluster_name  = module.eks.cluster_name
  addon_name    = "metrics-server"
  addon_version = var.metrics_server_version
}

resource "aws_autoscaling_group_tag" "cluster_autoscaler_label" {
  for_each               = { for node_group in var.eks_node_groups : node_group.name => node_group }
  depends_on             = [module.eks]
  autoscaling_group_name = module.eks.eks_managed_node_groups["${each.value.name}"].node_group_autoscaling_group_names[0]
  tag {
    key                 = "k8s.io/cluster-autoscaler/node-template/label/${each.value.name}"
    value               = "true"
    propagate_at_launch = true
  }
}

resource "aws_autoscaling_group_tag" "cluster_autoscaler_taint" {
  for_each               = local.cluster_autoscaler_nodegroup_taints
  depends_on             = [module.eks]
  autoscaling_group_name = module.eks.eks_managed_node_groups[each.value.node_group_name].node_group_autoscaling_group_names[0]
  tag {
    key                 = "k8s.io/cluster-autoscaler/node-template/taint/${each.value.taint.key}"
    value               = "${each.value.taint.value}:${each.value.taint.effect}"
    propagate_at_launch = true
  }
}




# data "aws_iam_role" "karpenter" {
#   name       = "${var.deployment_id}-eks-nodes"
#   depends_on = [module.eks]
# }

# module "karpenter" {
#   source  = "terraform-aws-modules/eks/aws//modules/karpenter"
#   version = "20.8.5"
#   create  = var.eks_create && var.eks_create_karpenter

#   cluster_name                    = var.deployment_id
#   enable_irsa                     = true
#   irsa_oidc_provider_arn          = module.eks.oidc_provider_arn
#   irsa_namespace_service_accounts = ["kube-system:karpenter"]
#   create_iam_role                 = true
#   iam_role_name                   = "KarpenterController-${var.deployment_id}"
#   iam_role_description            = "IAM role for karpenter controller created by karpenter module"
#   create_node_iam_role            = false
#   node_iam_role_arn               = data.aws_iam_role.karpenter.arn
#   create_access_entry             = false
#   iam_policy_name                 = "KarpenterPolicy-${var.deployment_id}"
#   iam_policy_description          = "Karpenter controller IAM policy created by karpenter module"
#   iam_role_use_name_prefix        = false
#   node_iam_role_additional_policies = {
#     AmazonSSMManagedInstanceCore = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
#     AmazonEBSCSIDriverPolicy     = "arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"
#   }
#   enable_spot_termination = true
#   queue_name              = "${var.deployment_id}-node-termination-handler"
# }



output "cluster_autoscaler_iam_role_arn" {
  value = var.eks_create && var.eks_create_cluster_autoscaler_irsa ? module.cluster_autoscaler_irsa[0].iam_role_arn : ""
}

output "external_dns_iam_role_arn" {
  value = var.eks_create && var.eks_create_external_dns_irsa ? module.external_dns_irsa[0].iam_role_arn : ""
}

output "load_balancer_controller_iam_role_arn" {
  value = var.eks_create && var.eks_create_load_balancer_controller_irsa ? module.load_balancer_controller_irsa[0].iam_role_arn : ""
}

output "karpenter_iam_role_arn" {
  value = ""
}

output "cluster_endpoint" {
  value = module.eks.cluster_endpoint
}

output "cluster_name" {
  value = module.eks.cluster_name
}

output "cluster_certificate_authority_data" {
  value = module.eks.cluster_certificate_authority_data
}

output "nodegroup_iam_role_name" {
  value = ""
}

output "eks" {
  value = module.eks
}
