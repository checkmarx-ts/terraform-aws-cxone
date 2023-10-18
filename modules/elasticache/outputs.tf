output "redis_private_endpoint" {
  value = aws_elasticache_replication_group.redis.configuration_endpoint_address
}