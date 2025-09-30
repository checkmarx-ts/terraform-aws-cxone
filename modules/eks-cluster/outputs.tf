output "cluster_primary_security_group_id" {
  value = module.eks.cluster_primary_security_group_id
}

output "cluster_security_group_id" {
  value = module.eks.cluster_security_group_id
}

output "cluster_endpoint" {
  value = module.eks.cluster_endpoint
}

output "cluster_certificate_authority_data" {
  value = module.eks.cluster_certificate_authority_data
}

output "cluster_version" {
  value = module.eks.cluster_version
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

output "cluster_service_cidr" {
  value = module.eks.cluster_service_cidr
}