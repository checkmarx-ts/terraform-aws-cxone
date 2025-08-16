

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}


resource "aws_opensearch_domain" "es" {
  domain_name    = var.deployment_id
  engine_version = var.engine_version

  cluster_config {
    instance_type                 = var.instance_type
    dedicated_master_enabled      = var.enable_dedicated_master_nodes
    dedicated_master_count        = var.dedicated_master_count
    dedicated_master_type         = var.dedicated_master_type
    instance_count                = var.instance_count
    multi_az_with_standby_enabled = false
    zone_awareness_enabled        = true

    zone_awareness_config {
      availability_zone_count = min(length(var.subnet_ids), var.instance_count)
    }
  }

  vpc_options {
    subnet_ids         = var.subnet_ids
    security_group_ids = var.security_group_ids
  }

  ebs_options {
    ebs_enabled = true
    volume_type = "gp3"
    volume_size = var.volume_size
    throughput  = var.ebs_throughput
    iops        = var.ebs_iops
  }

  domain_endpoint_options {
    enforce_https       = true
    tls_security_policy = var.tls_security_policy
  }

  advanced_options = {
    "rest.action.multi.allow_explicit_index" = "true"
  }

  encrypt_at_rest {
    enabled = true
  }

  node_to_node_encryption {
    enabled = true
  }

  advanced_security_options {
    enabled                        = true
    internal_user_database_enabled = true
    anonymous_auth_enabled         = false
    master_user_options {
      master_user_name     = var.username
      master_user_password = var.password
    }
  }


  access_policies = <<CONFIG
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": "es:*",
            "Principal": "*",
            "Effect": "Allow",
            "Resource": "arn:${data.aws_partition.current.partition}:es:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:domain/${var.deployment_id}/*"
        }
    ]
}
CONFIG

  dynamic "log_publishing_options" {
    for_each = var.log_publishing_options
    iterator = lpo
    content {
      log_type                 = lpo.key
      cloudwatch_log_group_arn = lpo.value.cloudwatch_log_group_arn
      enabled                  = try(lpo.value.enabled, true)
    }
  }

  tags = {
    Domain = var.deployment_id
  }
}
