# ---------------------------------------------------------------------------------------------------------------------
# IAM Role for the EKS Nodegroup nodes
# ---------------------------------------------------------------------------------------------------------------------

locals {
  node_role_name = split("/", var.node_role_arn == null ? aws_iam_role.eks_nodes[0].arn : var.node_role_arn)[1]
}

# ---------------------------------------------------------------------------------------------------------------------
# Related Variables & Outputs
# ---------------------------------------------------------------------------------------------------------------------

variable "node_role_arn" {
  type        = string
  description = "The pre-existing IAM role arn for the EKS Nodes. A role will be created if not provided."
  default     = null
}

variable "node_role_permissions_boundary_policy_arn" {
  description = "The permissions boundary policy arn for the EKS Nodes IAM role."
  type        = string
  default     = null
}

output "eks_nodes_iam_role_arn" {
  value = var.node_role_arn == null ? aws_iam_role.eks_nodes[0].arn : var.node_role_arn
}

output "eks_nodes_iam_role_name" {
  value = local.node_role_name
}

# ---------------------------------------------------------------------------------------------------------------------
# Related Resources
# ---------------------------------------------------------------------------------------------------------------------

# AmazonAPIGatewayPushToCloudWatchLogs
data "aws_iam_policy" "AmazonAPIGatewayPushToCloudWatchLogs" {
  count = var.node_role_arn == null ? 1 : 0
  arn   = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs"
}

resource "aws_iam_role_policy_attachment" "EksNodesAmazonAPIGatewayPushToCloudWatchLogs" {
  count      = var.node_role_arn == null ? 1 : 0
  role       = aws_iam_role.eks_nodes[0].name
  policy_arn = data.aws_iam_policy.AmazonAPIGatewayPushToCloudWatchLogs[0].arn
}


# AmazonEKSWorkerNodePolicy
data "aws_iam_policy" "AmazonEKSWorkerNodePolicy" {
  count = var.node_role_arn == null ? 1 : 0
  arn   = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonEKSWorkerNodePolicy"
}

resource "aws_iam_role_policy_attachment" "EksNodesAmazonEKSWorkerNodePolicy" {
  count      = var.node_role_arn == null ? 1 : 0
  role       = aws_iam_role.eks_nodes[0].name
  policy_arn = data.aws_iam_policy.AmazonEKSWorkerNodePolicy[0].arn
}


# AmazonSSMManagedInstanceCore
data "aws_iam_policy" "AmazonSSMManagedInstanceCore" {
  count = var.node_role_arn == null ? 1 : 0
  arn   = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy_attachment" "EksNodesAmazonSSMManagedInstanceCore" {
  count      = var.node_role_arn == null ? 1 : 0
  role       = aws_iam_role.eks_nodes[0].name
  policy_arn = data.aws_iam_policy.AmazonSSMManagedInstanceCore[0].arn
}


# AmazonEC2ContainerRegistryReadOnly
data "aws_iam_policy" "AmazonEC2ContainerRegistryReadOnly" {
  count = var.node_role_arn == null ? 1 : 0
  arn   = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

resource "aws_iam_role_policy_attachment" "EksNodesAmazonEC2ContainerRegistryReadOnly" {
  count      = var.node_role_arn == null ? 1 : 0
  role       = aws_iam_role.eks_nodes[0].name
  policy_arn = data.aws_iam_policy.AmazonEC2ContainerRegistryReadOnly[0].arn
}

# Customer managed policy to allow access to s3 buckets for the deployment.
resource "aws_iam_policy" "ast_s3_buckets_policy" {
  count = var.node_role_arn == null ? 1 : 0
  name  = "${var.deployment_id}-s3-access"
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

resource "aws_iam_role_policy_attachment" "ast_s3_buckets_policy_attachment" {
  count      = var.node_role_arn == null ? 1 : 0
  role       = aws_iam_role.eks_nodes[0].name
  policy_arn = aws_iam_policy.ast_s3_buckets_policy[0].arn
}


# IAM Role & Profile
resource "aws_iam_role" "eks_nodes" {
  count                = var.node_role_arn == null ? 1 : 0
  name                 = "${var.deployment_id}-eks-nodes"
  description          = "IAM Role for Checkmarx One EKS Nodes"
  permissions_boundary = var.node_role_permissions_boundary_policy_arn
  assume_role_policy   = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_iam_instance_profile" "eks_nodes" {
  count = var.node_role_arn == null ? 1 : 0
  name  = "${var.deployment_id}-eks-nodes"
  role  = aws_iam_role.eks_nodes[0].name
}
