# ---------------------------------------------------------------------------------------------------------------------
# IAM Role for the EKS Cluster
# ---------------------------------------------------------------------------------------------------------------------

locals {
  cluster_role_name = split("/", var.cluster_role_arn == null ? aws_iam_role.eks_cluster[0].arn : var.cluster_role_arn)[1]
}

# ---------------------------------------------------------------------------------------------------------------------
# Related Variables & Outputs
# ---------------------------------------------------------------------------------------------------------------------

variable "cluster_role_arn" {
  type        = string
  description = "The pre-existing IAM role arn for the EKS Cluster. A cluster role will be created if not provided."
  default     = null
}

output "eks_cluster_iam_role_arn" {
  value = var.cluster_role_arn == null ? aws_iam_role.eks_cluster[0].arn : var.cluster_role_arn
}

output "eks_cluster_iam_role_name" {
  value = local.cluster_role_name
}

# ---------------------------------------------------------------------------------------------------------------------
# Related Resources
# ---------------------------------------------------------------------------------------------------------------------
# AmazonEKSClusterPolicy
data "aws_iam_policy" "AmazonEKSClusterPolicy" {
  count = var.cluster_role_arn == null ? 1 : 0
  arn   = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonEKSClusterPolicy"
}

resource "aws_iam_role_policy_attachment" "AmazonEKSClusterPolicy" {
  count      = var.cluster_role_arn == null ? 1 : 0
  role       = aws_iam_role.eks_cluster[0].name
  policy_arn = data.aws_iam_policy.AmazonEKSClusterPolicy[0].arn
}

# AmazonEKSVPCResourceController
data "aws_iam_policy" "AmazonEKSVPCResourceController" {
  count = var.cluster_role_arn == null ? 1 : 0
  arn   = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonEKSVPCResourceController"
}

resource "aws_iam_role_policy_attachment" "AmazonEKSVPCResourceController" {
  count      = var.cluster_role_arn == null ? 1 : 0
  role       = aws_iam_role.eks_cluster[0].name
  policy_arn = data.aws_iam_policy.AmazonEKSVPCResourceController[0].arn
}

# ClusterEncryption - must be customer managed policy to scope to specific KMS key 
resource "aws_iam_policy" "cluster_encryption" {
  count = var.cluster_role_arn == null ? 1 : 0
  name  = "${var.deployment_id}-cluster-encyrption"
  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Action" : [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ListGrants",
          "kms:DescribeKey"
        ],
        "Effect" : "Allow",
        "Resource" : [
          "${var.eks_kms_key_arn}"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "cluster_encryption" {
  count      = var.cluster_role_arn == null ? 1 : 0
  role       = aws_iam_role.eks_cluster[0].name
  policy_arn = aws_iam_policy.cluster_encryption[0].arn
}

# Cluster Role & Profile
resource "aws_iam_role" "eks_cluster" {
  count              = var.cluster_role_arn == null ? 1 : 0
  name               = "${var.deployment_id}-eks-cluster"
  description        = "IAM Role for Checkmarx One EKS Cluster for deployment id ${var.deployment_id}"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EKSClusterAssumeRole",
      "Action": "sts:AssumeRole",
      "Effect": "Allow",
      "Principal": {
        "Service": "eks.amazonaws.com"
      }
    }
  ]
}
EOF
}

resource "aws_iam_instance_profile" "eks_cluster" {
  count = var.cluster_role_arn == null ? 1 : 0
  name  = "${var.deployment_id}-eks-cluster"
  role  = aws_iam_role.eks_cluster[0].name
}
