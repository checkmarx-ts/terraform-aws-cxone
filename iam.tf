# VPC CNI Pod Identity
module "vpc_cni_pod_identity" {
  source  = "terraform-aws-modules/eks-pod-identity/aws"
  version = "1.10.0"

  name                      = "${var.deployment_id}-vpc-cni"
  use_name_prefix           = false
  description               = "VPC CNI IAM Role for EKS Pod Identity Agent for the CxOne deployment ${var.deployment_id}"
  attach_aws_vpc_cni_policy = true
  aws_vpc_cni_enable_ipv4   = true
  policy_name_prefix        = var.deployment_id
}

# EBS CSI Driver
module "ebs_csi_pod_identity" {
  source  = "terraform-aws-modules/eks-pod-identity/aws"
  version = "1.10.0"

  name                      = "${var.deployment_id}-ebs-csi"
  use_name_prefix           = false
  description               = "EBS CSI IAM Role for EKS Pod Identity Agent for the CxOne deployment ${var.deployment_id}"
  attach_aws_ebs_csi_policy = true
  aws_ebs_csi_kms_arns      = [var.kms_key_arn]
  policy_name_prefix        = var.deployment_id
}


module "eks_node_iam_role" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-assumable-role"
  version = "5.48.0"
  trusted_role_services = [
    "ec2.amazonaws.com"
  ]
  create_role       = true
  role_name         = "${var.deployment_id}-eks-nodes"
  role_requires_mfa = false
  custom_role_policy_arns = [
    "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs",
    "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonEKSWorkerNodePolicy",
    "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore",
    "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  ]
}

resource "aws_iam_role_policy_attachment" "s3_access" {
  count      = var.create_node_s3_iam_role == true ? 1 : 0
  role       = module.eks_node_iam_role.iam_role_name
  policy_arn = aws_iam_policy.s3_bucket_access[0].arn
}


resource "aws_iam_policy" "s3_bucket_access" {
  name  = "${var.deployment_id}-s3-access"
  count = var.create_node_s3_iam_role == true ? 1 : 0
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


module "cluster_autoscaler_irsa" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "5.48.0"
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
  version = "5.48.0"
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
  version = "5.48.0"
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

module "aws_cloudwatch_observability_irsa" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "5.48.0"
  count   = var.eks_create && var.aws_cloudwatch_observability_version != null ? 1 : 0

  role_name                              = "aws-cloudwatch-observability-${var.deployment_id}"
  role_description                       = "IRSA role for AWS Cloudwatch Observability"
  attach_cloudwatch_observability_policy = true
  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["amazon-cloudwatch:cloudwatch-agent"]
    }
  }
}
