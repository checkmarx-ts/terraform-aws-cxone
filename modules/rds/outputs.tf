
output "cluster_id" {
  value = module.rds-aurora.cluster_id
}

output "cluster_endpoint" {
  value = module.rds-aurora.cluster_endpoint
}

output "cluster_port" {
  value = module.rds-aurora.cluster_port
}

output "cluster_reader_endpoint" {
  value = module.rds-aurora.cluster_reader_endpoint
}

output "cluster_database_name" {
  value = module.rds-aurora.cluster_database_name
}

output "cluster_master_username" {
  value = module.rds-aurora.cluster_master_username
}

output "cluster_master_password" {
  value     = module.rds-aurora.cluster_master_password
  sensitive = true
}

