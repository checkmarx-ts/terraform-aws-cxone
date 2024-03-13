output "cluster_access_iam_role_arn" {
  value = aws_iam_role.cluster_access_role.arn
}

output "eks_nodes_iam_role_arn" {
  value = aws_iam_role.eks_nodes.arn
}

output "eks_nodes_iam_role_name" {
  value = aws_iam_role.eks_nodes.name
}