data "aws_region" "current" {}

# AWS IAM POLICY FOR CLUSTER AUTOSCALER
resource "aws_iam_policy" "cluster_autoscaler" {
  name        = "${var.deployment_id}-eks-cluster-autoscaler-${data.aws_region.current.name}"
  description = "EKS Cluster Auto Scalers Policy for ${var.deployment_id}"
  policy      = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
        "Effect": "Allow",
        "Action": [
            "autoscaling:DescribeAutoScalingGroups",
            "autoscaling:DescribeAutoScalingInstances",
            "autoscaling:DescribeLaunchConfigurations",
            "autoscaling:DescribeScalingActivities",
            "autoscaling:DescribeTags",
            "ec2:DescribeInstanceTypes",
            "ec2:DescribeLaunchTemplateVersions"
        ],
        "Resource": ["*"]
        },
        {
        "Effect": "Allow",
        "Action": [
            "autoscaling:SetDesiredCapacity",
            "autoscaling:TerminateInstanceInAutoScalingGroup",
            "ec2:DescribeImages",
            "ec2:GetInstanceTypesFromInstanceRequirements",
            "eks:DescribeNodegroup"
        ],
        "Resource": ["*"]
        }
    ]
}
EOF
}
# AWS IAM ROLE FOR CLUTER AUTOSCALER
module "cluster_autoscaler_irsa" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "4.13.1"

  role_name        = "cluster-autoscaler-${var.deployment_id}"
  role_description = "IRSA role for cluster autoscaler"

  # setting to false because we don't want to rely on exeternal policies
  attach_cluster_autoscaler_policy = false
  cluster_autoscaler_cluster_ids   = [module.eks.cluster_id]
  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:cluster-autoscaler"]
    }
  }
}
# ATTACHE POLICY FOR AWS AIM ROLE FOR CLUSTER AUTOSCALER
resource "aws_iam_role_policy_attachment" "aws-cluster-autoscaler-policy-attachment" {
  role       = module.cluster_autoscaler_irsa.iam_role_name
  policy_arn = aws_iam_policy.cluster_autoscaler.arn
}
# HELM CLUSTER AUTOSCALER
resource "helm_release" "cluster-autoscaler" {
  depends_on = [
    module.cluster_autoscaler_irsa,
    aws_iam_role_policy_attachment.aws-cluster-autoscaler-policy-attachment
  ]
  count     = 1
  name      = "cluster-autoscaler"
  chart     = "${path.module}/helm-charts/cluster-autoscaler-9.21.1.tgz"
  version   = "9.21.1"
  namespace = "kube-system"

  set {
    name  = "image.tag"
    value = "v1.23.0"
  }

  set {
    name  = "autoDiscovery.clusterName"
    value = var.deployment_id
  }
  set {
    name  = "awsRegion"
    value = data.aws_region.current.name
  }

  set {
    name  = "rbac.create"
    value = "true"
  }
  set {
    name  = "rbac.serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.cluster_autoscaler_irsa.iam_role_arn
  }
  set {
    name  = "rbac.serviceAccount.create"
    value = "true"
  }
  set {
    name  = "rbac.serviceAccount.name"
    value = "cluster-autoscaler"
  }
}


#------------------------------------------------------------------------------
# Add additional tags to autoscaling groups for the managed nodes
#------------------------------------------------------------------------------

# KICS
resource "aws_autoscaling_group_tag" "kics_label" {
  depends_on             = [module.eks]
  autoscaling_group_name = module.eks.eks_managed_node_groups.kics.node_group_autoscaling_group_names[0]
  tag {
    key                 = "k8s.io/cluster-autoscaler/node-template/label/${var.kics_nodes.label_name}"
    value               = var.kics_nodes.label_value
    propagate_at_launch = true
  }
}

resource "aws_autoscaling_group_tag" "kics_taint" {
  depends_on             = [module.eks]
  autoscaling_group_name = module.eks.eks_managed_node_groups.kics.node_group_autoscaling_group_names[0]
  tag {
    key                 = "k8s.io/cluster-autoscaler/node-template/taint/${var.kics_nodes.key}"
    value               = "${var.kics_nodes.value}:${var.kics_nodes.effect}"
    propagate_at_launch = true
  }
}

# Metrics
resource "aws_autoscaling_group_tag" "metrics_label" {
  depends_on             = [module.eks]
  autoscaling_group_name = module.eks.eks_managed_node_groups.metrics.node_group_autoscaling_group_names[0]
  tag {
    key                 = "k8s.io/cluster-autoscaler/node-template/label/${var.metrics_nodes.label_name}"
    value               = var.metrics_nodes.label_value
    propagate_at_launch = true
  }
}

resource "aws_autoscaling_group_tag" "metrics_taint" {
  depends_on             = [module.eks]
  autoscaling_group_name = module.eks.eks_managed_node_groups.metrics.node_group_autoscaling_group_names[0]
  tag {
    key                 = "k8s.io/cluster-autoscaler/node-template/taint/${var.metrics_nodes.key}"
    value               = "${var.metrics_nodes.value}:${var.metrics_nodes.effect}"
    propagate_at_launch = true
  }
}

# Minio
resource "aws_autoscaling_group_tag" "minio_label" {
  depends_on             = [module.eks]
  autoscaling_group_name = module.eks.eks_managed_node_groups.minio.node_group_autoscaling_group_names[0]
  tag {
    key                 = "k8s.io/cluster-autoscaler/node-template/label/${var.minio_gateway_nodes.label_name}"
    value               = var.minio_gateway_nodes.label_value
    propagate_at_launch = true
  }
}

resource "aws_autoscaling_group_tag" "minio_taint" {
  depends_on             = [module.eks]
  autoscaling_group_name = module.eks.eks_managed_node_groups.minio.node_group_autoscaling_group_names[0]
  tag {
    key                 = "k8s.io/cluster-autoscaler/node-template/taint/${var.minio_gateway_nodes.key}"
    value               = "${var.minio_gateway_nodes.value}:${var.minio_gateway_nodes.effect}"
    propagate_at_launch = true
  }
}

# Reports
resource "aws_autoscaling_group_tag" "reports_label" {
  depends_on             = [module.eks]
  autoscaling_group_name = module.eks.eks_managed_node_groups.reports.node_group_autoscaling_group_names[0]
  tag {
    key                 = "k8s.io/cluster-autoscaler/node-template/label/${var.reports_nodes.label_name}"
    value               = var.reports_nodes.label_value
    propagate_at_launch = true
  }
}

resource "aws_autoscaling_group_tag" "reports_taint" {
  depends_on             = [module.eks]
  autoscaling_group_name = module.eks.eks_managed_node_groups.reports.node_group_autoscaling_group_names[0]
  tag {
    key                 = "k8s.io/cluster-autoscaler/node-template/taint/${var.reports_nodes.key}"
    value               = "${var.reports_nodes.value}:${var.reports_nodes.effect}"
    propagate_at_launch = true
  }
}

# Repostore
resource "aws_autoscaling_group_tag" "repostore_label" {
  depends_on             = [module.eks]
  autoscaling_group_name = module.eks.eks_managed_node_groups.reports.node_group_autoscaling_group_names[0]
  tag {
    key                 = "k8s.io/cluster-autoscaler/node-template/label/${var.repostore_nodes.label_name}"
    value               = var.repostore_nodes.label_value
    propagate_at_launch = true
  }
}

resource "aws_autoscaling_group_tag" "repostore_taint" {
  depends_on             = [module.eks]
  autoscaling_group_name = module.eks.eks_managed_node_groups.reports.node_group_autoscaling_group_names[0]
  tag {
    key                 = "k8s.io/cluster-autoscaler/node-template/taint/${var.repostore_nodes.key}"
    value               = "${var.repostore_nodes.value}:${var.repostore_nodes.effect}"
    propagate_at_launch = true
  }
}

# Sast Engines
resource "aws_autoscaling_group_tag" "sast_label" {
  depends_on             = [module.eks]
  autoscaling_group_name = module.eks.eks_managed_node_groups.sast_engines.node_group_autoscaling_group_names[0]
  tag {
    key                 = "k8s.io/cluster-autoscaler/node-template/label/${var.sast_nodes.label_name}"
    value               = var.sast_nodes.label_value
    propagate_at_launch = true
  }
}

resource "aws_autoscaling_group_tag" "sast_taint" {
  depends_on             = [module.eks]
  autoscaling_group_name = module.eks.eks_managed_node_groups.sast_engines.node_group_autoscaling_group_names[0]
  tag {
    key                 = "k8s.io/cluster-autoscaler/node-template/taint/${var.sast_nodes.key}"
    value               = "${var.sast_nodes.value}:${var.sast_nodes.effect}"
    propagate_at_launch = true
  }
}

# Sast Engines - Large
resource "aws_autoscaling_group_tag" "sast_large_label" {
  depends_on             = [module.eks]
  autoscaling_group_name = module.eks.eks_managed_node_groups.sast_engines_large.node_group_autoscaling_group_names[0]
  tag {
    key                 = "k8s.io/cluster-autoscaler/node-template/label/${var.sast_nodes_large.label_name}"
    value               = var.sast_nodes_large.label_value
    propagate_at_launch = true
  }
}

resource "aws_autoscaling_group_tag" "sast_large_taint" {
  depends_on             = [module.eks]
  autoscaling_group_name = module.eks.eks_managed_node_groups.sast_engines_large.node_group_autoscaling_group_names[0]
  tag {
    key                 = "k8s.io/cluster-autoscaler/node-template/taint/${var.sast_nodes_large.key}"
    value               = "${var.sast_nodes_large.value}:${var.sast_nodes_large.effect}"
    propagate_at_launch = true
  }
}

# Sast Engines - Large
resource "aws_autoscaling_group_tag" "sast_xlarge_label" {
  depends_on             = [module.eks]
  autoscaling_group_name = module.eks.eks_managed_node_groups.sast_engines_xl.node_group_autoscaling_group_names[0]
  tag {
    key                 = "k8s.io/cluster-autoscaler/node-template/label/${var.sast_nodes_extra_large.label_name}"
    value               = var.sast_nodes_extra_large.label_value
    propagate_at_launch = true
  }
}

resource "aws_autoscaling_group_tag" "sast_xlarge_taint" {
  depends_on             = [module.eks]
  autoscaling_group_name = module.eks.eks_managed_node_groups.sast_engines_xl.node_group_autoscaling_group_names[0]
  tag {
    key                 = "k8s.io/cluster-autoscaler/node-template/taint/${var.sast_nodes_extra_large.key}"
    value               = "${var.sast_nodes_extra_large.value}:${var.sast_nodes_extra_large.effect}"
    propagate_at_launch = true
  }
}

# Sast Engines - Large
resource "aws_autoscaling_group_tag" "sast_2xlarge_label" {
  depends_on             = [module.eks]
  autoscaling_group_name = module.eks.eks_managed_node_groups.sast_engines_2xl.node_group_autoscaling_group_names[0]
  tag {
    key                 = "k8s.io/cluster-autoscaler/node-template/label/${var.sast_nodes_xxl.label_name}"
    value               = var.sast_nodes_xxl.label_value
    propagate_at_launch = true
  }
}

resource "aws_autoscaling_group_tag" "sast_2xlarge_taint" {
  depends_on             = [module.eks]
  autoscaling_group_name = module.eks.eks_managed_node_groups.sast_engines_2xl.node_group_autoscaling_group_names[0]
  tag {
    key                 = "k8s.io/cluster-autoscaler/node-template/taint/${var.sast_nodes_xxl.key}"
    value               = "${var.sast_nodes_xxl.value}:${var.sast_nodes_xxl.effect}"
    propagate_at_launch = true
  }
}


# SCA
resource "aws_autoscaling_group_tag" "sca_label" {
  depends_on             = [module.eks]
  autoscaling_group_name = module.eks.eks_managed_node_groups.sca.node_group_autoscaling_group_names[0]
  tag {
    key                 = "k8s.io/cluster-autoscaler/node-template/label/${var.sca_nodes.label_name}"
    value               = var.sca_nodes.label_value
    propagate_at_launch = true
  }
}

resource "aws_autoscaling_group_tag" "sca_taint" {
  depends_on             = [module.eks]
  autoscaling_group_name = module.eks.eks_managed_node_groups.sca.node_group_autoscaling_group_names[0]
  tag {
    key                 = "k8s.io/cluster-autoscaler/node-template/taint/${var.sca_nodes.key}"
    value               = "${var.sca_nodes.value}:${var.sca_nodes.effect}"
    propagate_at_launch = true
  }
}

# DAST
resource "aws_autoscaling_group_tag" "dast_label" {
  depends_on             = [module.eks]
  autoscaling_group_name = module.eks.eks_managed_node_groups.dast.node_group_autoscaling_group_names[0]
  tag {
    key                 = "k8s.io/cluster-autoscaler/node-template/label/${var.dast_nodes.label_name}"
    value               = var.dast_nodes.label_value
    propagate_at_launch = true
  }
}

resource "aws_autoscaling_group_tag" "dast_taint" {
  depends_on             = [module.eks]
  autoscaling_group_name = module.eks.eks_managed_node_groups.dast.node_group_autoscaling_group_names[0]
  tag {
    key                 = "k8s.io/cluster-autoscaler/node-template/taint/${var.dast_nodes.key}"
    value               = "${var.dast_nodes.value}:${var.dast_nodes.effect}"
    propagate_at_launch = true
  }
}