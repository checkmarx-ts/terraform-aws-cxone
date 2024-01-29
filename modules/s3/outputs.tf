output "s3_bucket_name_suffix" {
  value = local.s3_bucket_name_suffix
}

output "engine_logs_bucket_id" {
  value = module.s3_bucket["engine_logs"].s3_bucket_id
}

output "uploads_bucket_id" {
  value = module.s3_bucket["uploads"].s3_bucket_id
}

output "queries_bucket_id" {
  value = module.s3_bucket["queries"].s3_bucket_id
}

output "misc_bucket_id" {
  value = module.s3_bucket["misc"].s3_bucket_id
}

output "repostore_bucket_id" {
  value = module.s3_bucket["repostore"].s3_bucket_id
}

output "sast_metadata_bucket_id" {
  value = module.s3_bucket["sast_metadata"].s3_bucket_id
}

output "scans_bucket_id" {
  value = module.s3_bucket["scans"].s3_bucket_id
}

output "sast_worker_bucket_id" {
  value = module.s3_bucket["sast_worker"].s3_bucket_id
}

output "kics_worker_bucket_id" {
  value = module.s3_bucket["kics_worker"].s3_bucket_id
}

output "sca_worker_bucket_id" {
  value = module.s3_bucket["sca_worker"].s3_bucket_id
}

output "logs_bucket_id" {
  value = module.s3_bucket["logs"].s3_bucket_id
}

output "reports_bucket_id" {
  value = module.s3_bucket["reports"].s3_bucket_id
}

output "report_templates_bucket_id" {
  value = module.s3_bucket["report_templates"].s3_bucket_id
}

output "configuration_bucket_id" {
  value = module.s3_bucket["configuration"].s3_bucket_id
}

output "imports_bucket_id" {
  value = module.s3_bucket["imports"].s3_bucket_id
}

output "audit_bucket_id" {
  value = module.s3_bucket["audit"].s3_bucket_id
}

output "source_resolver_bucket_id" {
  value = module.s3_bucket["source_resolver"].s3_bucket_id
}

output "api_security_bucket_id" {
  value = module.s3_bucket["api_security"].s3_bucket_id
}

output "redis_bucket_id" {
  value = module.s3_bucket["redis"].s3_bucket_id
}

output "scan_results_storage_bucket_id" {
  value = module.s3_bucket["scan_results_storage"].s3_bucket_id
}

output "export_bucket_id" {
  value = module.s3_bucket["export"].s3_bucket_id
}

output "cxone_bucket_id" {
  value = module.s3_bucket["cxone"].s3_bucket_id
}

