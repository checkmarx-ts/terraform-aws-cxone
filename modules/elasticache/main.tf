resource "aws_elasticache_subnet_group" "redis" {
  name       = var.deployment_id
  subnet_ids = var.subnet_ids
}

# tfsec:ignore:aws-elasticache-enable-in-transit-encryption
resource "aws_elasticache_replication_group" "redis" {
  replication_group_id = var.deployment_id
  description          = "Redis cluster for AST application"

  subnet_group_name = aws_elasticache_subnet_group.redis.name

  security_group_ids = var.security_group_ids

  node_type = var.redis_nodes.instance_type

  engine         = "redis"
  engine_version = "6.x"

  port                     = 6379
  parameter_group_name     = "default.redis6.x.cluster.on"
  snapshot_retention_limit = 2

  automatic_failover_enabled = true

  replicas_per_node_group = var.redis_nodes.replicas_per_shard
  num_node_groups         = var.redis_nodes.number_of_shards

  transit_encryption_enabled = var.redis_auth_token != "" ? true : false #BUG - AST can't work with TLS enabled
  auth_token                 = var.redis_auth_token != "" ? var.redis_auth_token : null

  kms_key_id                 = var.kms_key_arn
  at_rest_encryption_enabled = true


  apply_immediately = true

}