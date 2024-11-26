output "cluster_primary_security_group_id" {
  value = module.eks.cluster_primary_security_group_id
}

output "cluster_endpoint" {
  value = module.eks.cluster_endpoint
}

output "cluster_certificate_authority_data" {
  value = module.eks.cluster_certificate_authority_data
}

output "cluster_autoscaler_role_arn" {
  value = var.eks_create_cluster_autoscaler_irsa ? module.cluster_autoscaler_irsa[0].iam_role_arn : null
}

output "external_dns_role_arn" {
  value = var.eks_create_external_dns_irsa ? module.external_dns_irsa[0].iam_role_arn : null
}

output "load_balancer_controller_role_arn" {
  value = var.eks_create_load_balancer_controller_irsa ? module.load_balancer_controller_irsa[0].iam_role_arn : null
}

output "cluster_name" {
  value = module.eks.cluster_name
}

output "oidc_provider_arn" {
  value = module.eks.oidc_provider_arn
}

output "self_managed_node_groups" {
  value = module.eks.self_managed_node_groups.*
}

output "self_managed_node_groups_autoscaling_group_names" {
  value = module.eks.self_managed_node_groups_autoscaling_group_names.*
}