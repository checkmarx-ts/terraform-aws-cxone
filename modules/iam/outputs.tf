output "cluster_access_iam_role_arn" {
  value = var.create_cluster_access_role ? aws_iam_role.cluster_access_role[0].arn : null
}

output "eks_nodes_iam_role_arn" {
  value = var.create_node_role ? aws_iam_role.eks_nodes[0].arn : null
}

output "eks_nodes_iam_role_name" {
  value = var.create_node_role ? aws_iam_role.eks_nodes[0].name : null
}

output "ebs_csi_role_arn" {
  value = var.create_ebs_csi_irsa ? module.ebs_csi_irsa[0].iam_role_arn : null
}

output "cluster_autoscaler_role_arn" {
  value = var.create_cluster_autoscaler_irsa ? module.cluster_autoscaler_irsa[0].iam_role_arn : null
}

output "external_dns_role_arn" {
  value = var.create_external_dns_irsa ? module.external_dns_irsa[0].iam_role_arn : null
}

output "load_balancer_controller_role_arn" {
  value = var.create_load_balancer_controller_irsa ? module.load_balancer_controller_irsa[0].iam_role_arn : null
}
