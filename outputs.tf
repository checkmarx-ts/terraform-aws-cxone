output "bucket_suffix" {
  value = random_string.random_suffix.result
}

output "eks_cluster" {
  value = {
    cluster_arn = module.eks.cluster_arn
    cluster_certificate_authority_data = module.eks.cluster_certificate_authority_data
    cluster_endpoint = module.eks.cluster_endpoint
    cluster_name = module.eks.cluster_name
    cluster_version = module.eks.cluster_version
    cluster_primary_security_group_id = module.eks.cluster_primary_security_group_id
    cluster_security_group_id = module.eks.cluster_security_group_id
    node_security_group_arn = module.eks.node_security_group_arn
  }
}