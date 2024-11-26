resource "aws_elasticache_serverless_cache" "main" {
  engine = "redis"
  count  = var.ec_create && var.ec_enable_serverless ? 1 : 0
  name   = "${var.deployment_id}-redis-serverless"
  cache_usage_limits {
    data_storage {
      maximum = var.ec_serverless_max_storage
      unit    = "GB"
    }
    ecpu_per_second {
      maximum = var.ec_serverless_max_ecpu_per_second
    }
  }
  daily_snapshot_time      = "09:00"
  description              = "Elasticache cluster for Checkmarx One deployment called: ${var.deployment_id}"
  kms_key_id               = var.kms_key_arn
  major_engine_version     = "7"
  snapshot_retention_limit = 1
  security_group_ids       = [module.elasticache_security_group.security_group_id]
  subnet_ids               = var.ec_subnets
}


resource "aws_elasticache_subnet_group" "redis" {
  count      = var.ec_create && var.ec_enable_serverless == false ? 1 : 0
  name       = var.deployment_id
  subnet_ids = var.ec_subnets
}


# tfsec:ignore:aws-elasticache-enable-in-transit-encryption
resource "aws_elasticache_replication_group" "redis" {
  count                      = var.ec_create && var.ec_enable_serverless == false ? 1 : 0
  replication_group_id       = var.deployment_id
  description                = "Redis cluster for AST application"
  subnet_group_name          = aws_elasticache_subnet_group.redis[0].name
  security_group_ids         = [module.elasticache_security_group.security_group_id]
  node_type                  = var.ec_node_type
  engine                     = "redis"
  engine_version             = var.ec_engine_version
  port                       = 6379
  parameter_group_name       = var.ec_parameter_group_name
  snapshot_retention_limit   = 2
  automatic_failover_enabled = var.ec_automatic_failover_enabled
  multi_az_enabled           = var.ec_multi_az_enabled
  #num_cache_clusters         = 2
  replicas_per_node_group = var.ec_replicas_per_shard
  num_node_groups         = var.ec_number_of_shards

  transit_encryption_enabled = false #var.redis_auth_token != "" ? true : false #BUG - AST can't work with TLS enabled
  # auth_token                 = var.redis_auth_token != "" ? var.redis_auth_token : null
  # auth_token_update_strategy = "SET"

  # Per https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/at-rest-encryption.html
  # "The default (service managed) encryption is the only option available in the GovCloud (US) Regions."
  kms_key_id                 = data.aws_partition.current.partition == "aws-us-gov" ? null : var.kms_key_arn
  at_rest_encryption_enabled = true
  auto_minor_version_upgrade = var.ec_auto_minor_version_upgrade
  apply_immediately          = true
}

module "elasticache_security_group" {
  source              = "terraform-aws-modules/security-group/aws"
  create              = var.ec_create
  version             = "5.1.2"
  name                = "${var.deployment_id}-elasticache"
  description         = "Elasticache security group for Checkmarx One deployment named ${var.deployment_id}"
  vpc_id              = var.vpc_id
  ingress_cidr_blocks = data.aws_vpc.main.cidr_block_associations[*].cidr_block
  ingress_rules       = ["redis-tcp"]
}

# output "redis" {
#   value = {
#     address = aws_elasticache_serverless_cache.main[0].endpoint[0].address
#     port    = aws_elasticache_serverless_cache.main[0].endpoint[0].port
#   }
# }

output "ec_endpoint" {
  value = var.ec_create ? (var.ec_enable_serverless ? aws_elasticache_serverless_cache.main[0].endpoint[0].address : aws_elasticache_replication_group.redis[0].configuration_endpoint_address) : ""
}

output "ec" {
  value = var.ec_create ? aws_elasticache_replication_group.redis[0].* : null
}

output "ec_port" {
  value = 6379
}
