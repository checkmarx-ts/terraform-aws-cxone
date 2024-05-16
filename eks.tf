locals {
  fargate_profiles = {
    karpenter = {
      selectors = [
        { namespace = "karpenter" }
      ]
    }
    kube-system = {
      selectors = [
        { namespace = "kube-system" }
      ]
    }
  }
  core_dns_fargate_configuration_values = jsonencode({
    computeType = "Fargate"
    # Ensure that we fully utilize the minimum amount of resources that are supplied by
    # Fargate https://docs.aws.amazon.com/eks/latest/userguide/fargate-pod-configuration.html
    # Fargate adds 256 MB to each pod's memory reservation for the required Kubernetes
    # components (kubelet, kube-proxy, and containerd). Fargate rounds up to the following
    # compute configuration that most closely matches the sum of vCPU and memory requests in
    # order to ensure pods always have the resources that they need to run.
    resources = {
      limits = {
        cpu = "0.25"
        # We are targeting the smallest Task size of 512Mb, so we subtract 256Mb from the
        # request/limit to ensure we can fit within that task
        memory = "256M"
      }
      requests = {
        cpu = "0.25"
        # We are targeting the smallest Task size of 512Mb, so we subtract 256Mb from the
        # request/limit to ensure we can fit within that task
        memory = "256M"
      }
    }
  })

  # The EBS CSI Add On Controller pods can run on Fargate, but we must add a toleration to eks.amazonaws.com/compute-type=fargate
  # in addition to the existing tolerations. Documentation for EBS CSI Driver configuration schema can be obtained from AWS CLI
  # example: aws eks describe-addon-configuration --addon-name aws-ebs-csi-driver --addon-version v1.28.0-eksbuild.1 --query configurationSchema --output text
  ebs_csi_fargate_configuration_values = jsonencode({
    controller = {
      batching = false
      tolerations = [
        {
          key      = "CriticalAddonsOnly"
          operator = "Exists"
        },
        {
          effect            = "NoExecute"
          operator          = "Exists"
          tolerationSeconds = 300
        },
        {
          key      = "eks.amazonaws.com/compute-type"
          operator = "Equal"
          value    = "fargate"
          effect   = "NoSchedule"
  }] } })

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
}

module "eks_node_iam_role" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-assumable-role"
  version = "5.37.2"
  trusted_role_services = [
    "ec2.amazonaws.com"
  ]
  create_role       = true
  role_name         = "${var.deployment_id}-eks-nodes"
  role_requires_mfa = false
  custom_role_policy_arns = [
    "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy",
    "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs",
    "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonEKS_CNI_Policy",
    "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonEKSWorkerNodePolicy",
    "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore",
    "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
    aws_iam_policy.s3_bucket_access.arn
  ]
}

resource "aws_iam_policy" "s3_bucket_access" {
  name = "${var.deployment_id}-s3-access"
  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Action" : [
          "s3:*"
        ],
        "Effect" : "Allow",
        "Resource" : [
          "arn:${data.aws_partition.current.partition}:s3:::${var.deployment_id}*",
          "arn:${data.aws_partition.current.partition}:s3:::${var.deployment_id}*/*"
        ]
      }
    ]
  })
}

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "20.8.5"
  create  = var.eks_create

  cluster_name    = var.deployment_id
  cluster_version = var.eks_version

  cluster_enabled_log_types = ["audit", "api", "authenticator", "scheduler"]

  cluster_endpoint_private_access = var.eks_private_endpoint_enabled
  cluster_endpoint_public_access  = var.eks_public_endpoint_enabled

  vpc_id     = var.vpc_id
  subnet_ids = var.eks_subnets

  create_cluster_security_group = true
  #cluster_security_group_id     = var.cluster_security_group_id

  create_node_security_group = true
  #node_security_group_id     = module.eks_nodes_security_group.security_group_id


  node_security_group_additional_rules = {
    ingress_self_http80 = {
      description = "Node to node ingress http/80"
      protocol    = "tcp"
      from_port   = 80
      to_port     = 80
      type        = "ingress"
      self        = true
    }
    ingress_self_regosync = {
      description = "Node to node ingress http/81 (regosync service)"
      protocol    = "tcp"
      from_port   = 81
      to_port     = 81
      type        = "ingress"
      self        = true
    }
    ingress_self_feedback_kics = {
      description = "Node to node ingress http/86-88 (feedback-mfe, kics, sast results service)"
      protocol    = "tcp"
      from_port   = 86
      to_port     = 89
      type        = "ingress"
      self        = true
    }
    ingress_self_sast_audit_queries = {
      description = "Node to node ingress http/777-778 (sast audit queries service)"
      protocol    = "tcp"
      from_port   = 777
      to_port     = 778
      type        = "ingress"
      self        = true
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

  cluster_addons = {
    coredns = {
      addon_version        = var.coredns_version
      configuration_values = var.eks_enable_fargate ? local.core_dns_fargate_configuration_values : null
    }
    kube-proxy = {
      addon_version = var.kube_proxy_version
    }
    vpc-cni = {
      addon_version  = var.vpc_cni_version
      before_compute = var.eks_enable_custom_networking
      configuration_values = jsonencode({
        env = {
          AWS_VPC_K8S_CNI_CUSTOM_NETWORK_CFG = tostring(var.eks_enable_custom_networking)
          ENI_CONFIG_LABEL_DEF               = var.eks_enable_custom_networking ? "topology.kubernetes.io/zone" : ""
          AWS_VPC_K8S_CNI_EXTERNALSNAT       = var.eks_enable_externalsnat ? "true" : "false"
        }
      })
    }
    aws-ebs-csi-driver = {
      addon_version        = var.aws_ebs_csi_driver_version
      configuration_values = var.eks_enable_fargate ? local.ebs_csi_fargate_configuration_values : null
    }
  }
  create_kms_key = false
  cluster_encryption_config = {
    "resources"      = ["secrets"]
    provider_key_arn = var.kms_key_arn
  }
  eks_managed_node_group_defaults = {
    vpc_security_group_ids          = var.eks_node_additional_security_group_ids
    use_name_prefix                 = false
    iam_role_use_name_prefix        = false
    launch_template_use_name_prefix = false
    launch_template_tags            = var.launch_template_tags
    cluster_name                    = var.deployment_id
    cluster_version                 = var.eks_version
    subnet_ids                      = var.eks_subnets
    create_iam_role                 = false
    iam_role_arn                    = module.eks_node_iam_role.iam_role_arn
    key_name                        = var.ec2_key_name
    post_bootstrap_user_data        = var.eks_post_bootstrap_user_data
    pre_bootstrap_user_data         = var.eks_pre_bootstrap_user_data
    metadata_options = {
      http_endpoint               = "enabled"
      http_tokens                 = "required"
      instance_metadata_tags      = "disabled"
      http_put_response_hop_limit = "2"
    }
  }

  cluster_security_group_additional_rules = var.eks_cluster_security_group_additional_rules
  eks_managed_node_groups                 = local.eks_nodegroups

  fargate_profile_defaults = {
    subnet_ids = var.eks_enable_custom_networking ? var.eks_pod_subnets : null
  }
  fargate_profiles = var.eks_enable_fargate ? local.fargate_profiles : {}
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
  for_each               = { for node_group in var.eks_node_groups : node_group.name => node_group if length(node_group.taints) > 0 }
  depends_on             = [module.eks]
  autoscaling_group_name = module.eks.eks_managed_node_groups["${each.value.name}"].node_group_autoscaling_group_names[0]
  tag {
    key                 = "k8s.io/cluster-autoscaler/node-template/taint/${each.value.taints.dedicated.key}"
    value               = "${each.value.taints.dedicated.value}:${each.value.taints.dedicated.effect}"
    propagate_at_launch = true
  }
}


module "cluster_autoscaler_irsa" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "5.39.0"
  count   = var.eks_create && var.eks_create_cluster_autoscaler_irsa ? 1 : 0

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
  version = "5.39.0"
  count   = var.eks_create && var.eks_create_external_dns_irsa ? 1 : 0

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
  version = "5.39.0"
  count   = var.eks_create && var.eks_create_load_balancer_controller_irsa ? 1 : 0

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

data "aws_iam_role" "karpenter" {
  name       = "${var.deployment_id}-eks-nodes"
  depends_on = [module.eks]
}

module "karpenter" {
  source  = "terraform-aws-modules/eks/aws//modules/karpenter"
  version = "20.8.5"
  create  = var.eks_create && var.eks_create_karpenter

  cluster_name                    = var.deployment_id
  enable_irsa                     = true
  irsa_oidc_provider_arn          = module.eks.oidc_provider_arn
  irsa_namespace_service_accounts = ["kube-system:karpenter"]
  create_iam_role                 = true
  iam_role_name                   = "KarpenterController-${var.deployment_id}"
  iam_role_description            = "IAM role for karpenter controller created by karpenter module"
  create_node_iam_role            = false
  node_iam_role_arn               = data.aws_iam_role.karpenter.arn
  create_access_entry             = false
  iam_policy_name                 = "KarpenterPolicy-${var.deployment_id}"
  iam_policy_description          = "Karpenter controller IAM policy created by karpenter module"
  iam_role_use_name_prefix        = false
  node_iam_role_additional_policies = {
    AmazonSSMManagedInstanceCore = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
    AmazonEBSCSIDriverPolicy     = "arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"
  }
  enable_spot_termination = true
  queue_name              = "${var.deployment_id}-node-termination-handler"
}



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
  value = var.eks_create && var.eks_create_karpenter ? module.karpenter.iam_role_arn : ""
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
  value = data.aws_iam_role.karpenter.name
}

output "eks" {
  value = module.eks
}
