# ---------------------------------------------------------------------------------------------------------------------
# IAM Role for the EKS Nodegroup nodes
# ---------------------------------------------------------------------------------------------------------------------
data "aws_partition" "current" {}

data "aws_iam_policy" "AmazonAPIGatewayPushToCloudWatchLogs" {
  arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs"
}
data "aws_iam_policy" "AmazonEKS_CNI_Policy" {
  arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonEKS_CNI_Policy"
}
data "aws_iam_policy" "AmazonEKSWorkerNodePolicy" {
  arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonEKSWorkerNodePolicy"
}
data "aws_iam_policy" "AmazonSSMManagedInstanceCore" {
  arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

data "aws_iam_policy" "AmazonEC2ContainerRegistryReadOnly" {
  arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}



resource "aws_iam_role_policy_attachment" "EksNodesAmazonAPIGatewayPushToCloudWatchLogs" {
  role       = aws_iam_role.eks_nodes.name
  policy_arn = data.aws_iam_policy.AmazonAPIGatewayPushToCloudWatchLogs.arn
}

resource "aws_iam_role_policy_attachment" "EksNodesAmazonEKS_CNI_Policy" {
  role       = aws_iam_role.eks_nodes.name
  policy_arn = data.aws_iam_policy.AmazonEKS_CNI_Policy.arn
}

resource "aws_iam_role_policy_attachment" "EksNodesAmazonEKSWorkerNodePolicy" {
  role       = aws_iam_role.eks_nodes.name
  policy_arn = data.aws_iam_policy.AmazonEKSWorkerNodePolicy.arn
}

resource "aws_iam_role_policy_attachment" "EksNodesAmazonSSMManagedInstanceCore" {
  role       = aws_iam_role.eks_nodes.name
  policy_arn = data.aws_iam_policy.AmazonSSMManagedInstanceCore.arn
}

resource "aws_iam_role_policy_attachment" "EksNodesAmazonEC2ContainerRegistryReadOnly" {
  role       = aws_iam_role.eks_nodes.name
  policy_arn = data.aws_iam_policy.AmazonEC2ContainerRegistryReadOnly.arn
}




# Policy to Allow Minio Nodegroup to aceess the S3 Buckets
resource "aws_iam_policy" "ast_s3_buckets_policy" {
  name = "${var.deployment_id}-eks-ng-minio-gateway-S3"
  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Action" : [
          "s3:*"
        ],
        "Effect" : "Allow",
        "Resource" : [
          "arn:${data.aws_partition.current.partition}:s3:::*${lower(var.s3_bucket_name_suffix)}",
          "arn:${data.aws_partition.current.partition}:s3:::*${lower(var.s3_bucket_name_suffix)}/*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ast_s3_buckets_policy_attachment" {
  role       = aws_iam_role.eks_nodes.name
  policy_arn = aws_iam_policy.ast_s3_buckets_policy.arn
}

resource "aws_iam_role" "eks_nodes" {
  name               = "${var.deployment_id}-eks-nodes"
  description        = "IAM Role for Checkmarx One EKS Nodes"
  assume_role_policy = <<EOF
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
  name = "${var.deployment_id}-eks-nodes"
  role = aws_iam_role.eks_nodes.name
}