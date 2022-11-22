output "aws_region" {
  description = "AWS Region where the infra was deployed"
  value       = var.aws_region
}
output "postgres-primary-endpoint" {
  description = "Postgres cluster primary endpoint"
  value       = module.rds-aurora.cluster_endpoint
}

output "postgres-reader-endpoint" {
  description = "Postgres cluster reader endpoint"
  value       = module.rds-aurora.cluster_reader_endpoint
}

output "postgres-database-name" {
  description = "Name of the database"
  value       = nonsensitive(var.database_name)
}

output "redis-private-endpoint" {
  description = "Redis cluster private endpoint"
  value       = try(aws_elasticache_replication_group.redis[0].configuration_endpoint_address, null)
}

output "eks_cluster_id" {
  value       = module.eks.cluster_id
  description = "EKS Cluster ID"
}

output "eks_cluster_arn" {
  value       = module.eks.cluster_arn
  description = "EKS Cluster ARN"
}

output "eks_cluster_endpoint" {
  value       = module.eks.cluster_endpoint
  description = "EKS Cluster Endpoint"
}

output "oidc_provider_arn" {
  value = module.eks.oidc_provider_arn
}
# Nodegroups
# AST
output "ast_default_autoscaling_group_name" {
  value = module.ast_default.node_group_autoscaling_group_names[0]
}
output "ast_default_autoscaling_group_min_size" {
  value = var.ast_nodes.min_size
}
output "ast_default_autoscaling_group_max_size" {
  value = var.ast_nodes.max_size
}

# SAST
output "ast_sast_engines_autoscaling_group_name" {
  value = module.ast_sast_engines.node_group_autoscaling_group_names[0]
}
output "ast_sast_engines_autoscaling_group_min_size" {
  value = var.sast_nodes.min_size
}
output "ast_sast_engines_autoscaling_group_max_size" {
  value = var.sast_nodes.max_size
}

# SAST Medium
output "ast_sast_medium_engines_autoscaling_group_name" {
  value = module.ast_sast_medium_engines.node_group_autoscaling_group_names[0]
}
output "ast_sast_medium_engines_autoscaling_group_min_size" {
  value = var.sast_nodes_medium.min_size
}
output "ast_sast_medium_engines_autoscaling_group_max_size" {
  value = var.sast_nodes_medium.max_size
}

# SAST Large
output "ast_sast_large_engines_autoscaling_group_name" {
  value = module.ast_sast_large_engines.node_group_autoscaling_group_names[0]
}
output "ast_sast_large_engines_autoscaling_group_min_size" {
  value = var.sast_nodes_large.min_size
}
output "ast_sast_large_engines_autoscaling_group_max_size" {
  value = var.sast_nodes_large.max_size
}

# SAST ExtraLarge
output "ast_sast_extra_large_engines_autoscaling_group_name" {
  value = module.ast_sast_extra_large_engines.node_group_autoscaling_group_names[0]
}
output "ast_sast_extra_large_engines_autoscaling_group_min_size" {
  value = var.sast_nodes_extra_large.min_size
}
output "ast_sast_extra_large_engines_autoscaling_group_max_size" {
  value = var.sast_nodes_extra_large.max_size
}

# SAST XXL
output "ast_sast_xxl_engines_autoscaling_group_name" {
  value = module.ast_sast_xxl_engines.node_group_autoscaling_group_names[0]
}
output "ast_sast_xxl_engines_autoscaling_group_min_size" {
  value = var.sast_nodes_xxl.min_size
}
output "ast_sast_xxl_engines_autoscaling_group_max_size" {
  value = var.sast_nodes_xxl.max_size
}

# KICS
output "kics_nodes_engines_autoscaling_group_name" {
  value = module.kics_nodes_engines.node_group_autoscaling_group_names[0]
}
output "kics_nodes_engines_autoscaling_group_min_size" {
  value = var.kics_nodes.min_size
}
output "kics_nodes_engines_autoscaling_group_max_size" {
  value = var.kics_nodes.max_size
}

# MINIO
output "minio_gateway_nodes_autoscaling_group_name" {
  value = module.minio_gateway_nodes.node_group_autoscaling_group_names[0]
}
output "minio_gateway_nodes_autoscaling_group_min_size" {
  value = var.minio_gateway_nodes.min_size
}
output "minio_gateway_nodes_autoscaling_group_max_size" {
  value = var.minio_gateway_nodes.max_size
}

# UPLOADS BUCKET
output "uploads_s3_bucket_name" {
  value       = aws_s3_bucket.uploads_bucket.id
  description = "S3 Bucket Name"
}
# QUERIES BUCKET
output "queries_s3_bucket_name" {
  value       = aws_s3_bucket.queries_bucket.id
  description = "S3 Bucket Name"
}
# MISC BUCKET
output "misc_s3_bucket_name" {
  value       = aws_s3_bucket.misc_bucket.id
  description = "S3 Bucket Name"
}

# REPOSTORE BUCKET
output "repostore_s3_bucket_name" {
  value       = aws_s3_bucket.repostore_bucket.id
  description = "S3 Bucket Name"
}

# SAST-METADATA BUCKET
output "sast_metadata_s3_bucket_name" {
  value       = aws_s3_bucket.sast_metadata_bucket.id
  description = "S3 Bucket Name"
}

# SCANS BUCKET
output "scans_s3_bucket_name" {
  value       = aws_s3_bucket.scans_bucket.id
  description = "S3 Bucket Name"
}

# SAST-WORKER BUCKET
output "sast_worker_s3_bucket_name" {
  value       = aws_s3_bucket.sast_worker_bucket.id
  description = "S3 Bucket Name"
}

# KICS-WORKER BUCKET
output "kics_worker_s3_bucket_name" {
  value       = aws_s3_bucket.kics_worker_bucket.id
  description = "S3 Bucket Name"
}

# SCA-WORKER BUCKET
output "sca_worker_s3_bucket_name" {
  value       = aws_s3_bucket.sca_worker_bucket.id
  description = "S3 Bucket Name"
}

# LOGS BUCKET
output "logs_s3_bucket_name" {
  value       = aws_s3_bucket.logs_bucket.id
  description = "S3 Bucket Name"
}

# ENGINE-LOGS BUCKET
output "engine_logs_s3_bucket_name" {
  value       = aws_s3_bucket.engine_logs_bucket.id
  description = "S3 Bucket Name"
}

# REPORTS BUCKET
output "reports_s3_bucket_name" {
  value       = aws_s3_bucket.reports_bucket.id
  description = "S3 Bucket Name"
}

# REPORT-TEMPLATES BUCKET
output "report_templates_s3_bucket_name" {
  value       = aws_s3_bucket.report_templates_bucket.id
  description = "S3 Bucket Name"
}

# CONFIGURATION BUCKET
output "configuration_s3_bucket_name" {
  value       = aws_s3_bucket.configuration_bucket.id
  description = "S3 Bucket Name"
}

# IMPORTS BUCKET
output "imports_s3_bucket_name" {
  value       = aws_s3_bucket.imports_bucket.id
  description = "S3 Bucket Name"
}

# AUDIT BUCKET
output "audit_s3_bucket_name" {
  value       = aws_s3_bucket.audit_bucket.id
  description = "S3 Bucket Name"
}

# SOURCE-RESOLVER BUCKET 
output "source_resolver_s3_bucket_name" {
  value       = aws_s3_bucket.source_resolver_bucket.id
  description = "S3 Bucket Name"
}

# APISEC BUCET 
output "apisec_s3_bucket_name" {
  value       = aws_s3_bucket.apisec_bucket.id
  description = "S3 Bucket Name"
}

# KICS-MATADATA BUCKET
output "kics_metadata_s3_bucket_name" {
  value       = aws_s3_bucket.kics_metadata_bucket.id
  description = "S3 Bucket Name"
}

# REDIS-SHARED-BUCKET
output "redis_shared_s3_bucket_name" {
  value       = aws_s3_bucket.redis_shared_bucket.id
  description = "S3 Bucket Name"
}

# SCAN RESULTS STORAGE BUCKET
output "scan_results_storage_s3_bucket_name" {
  value       = aws_s3_bucket.scan_results_storage_bucket.id
  description = "S3 Bucket Name"
}
