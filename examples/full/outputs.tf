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

output "s3_bucket_names" {
  description = "Names of all S3 buckets created for this deployment."
  value       = module.checkmarx-one.s3_bucket_names
}

output "rds_cluster_identifier" {
  description = "Aurora cluster identifier for the main (ast) database."
  value       = module.checkmarx-one.rds_cluster_identifier
}

output "rds_analytics_cluster_identifier" {
  description = "Aurora cluster identifier for the analytics database."
  value       = module.checkmarx-one.rds_analytics_cluster_identifier
}

