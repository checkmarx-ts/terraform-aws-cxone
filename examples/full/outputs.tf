output "cluster_name" {
  value = module.checkmarx-one.cluster_name
}

output "cluster_endpoint" {
  value = module.checkmarx-one.cluster_endpoint
}

output "cluster_certificate_authority_data" {
  value = module.checkmarx-one.cluster_certificate_authority_data
}

output "eks_cluster" {
  value = module.checkmarx-one.eks_cluster
}

