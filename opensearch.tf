resource "aws_elasticsearch_domain" "es" {
  count                 = var.es_create ? 1 : 0
  domain_name           = var.deployment_id
  elasticsearch_version = "7.10"

  cluster_config {
    dedicated_master_enabled = var.es_enable_dedicated_master_nodes
    dedicated_master_count   = var.es_dedicated_master_count
    dedicated_master_type    = var.es_dedicated_master_type
    instance_type            = var.es_instance_type
    instance_count           = var.es_instance_count
    zone_awareness_enabled   = true
    zone_awareness_config {
      availability_zone_count = min(length(var.es_subnets), var.es_instance_count)
    }
  }
  vpc_options {
    subnet_ids         = slice(var.es_subnets, 0, var.es_instance_count)
    security_group_ids = [module.elasticsearch_security_group.security_group_id]
  }
  snapshot_options {
    automated_snapshot_start_hour = 06
  }
  ebs_options {
    ebs_enabled = true
    volume_type = "gp3"
    volume_size = var.es_volume_size
    throughput  = 125
    iops        = 3000
  }
  domain_endpoint_options {
    enforce_https       = true
    tls_security_policy = var.es_tls_security_policy
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
    master_user_options {
      master_user_name     = var.es_username
      master_user_password = var.es_password
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

  tags = {
    Domain = var.deployment_id
  }
}

module "elasticsearch_security_group" {
  source              = "terraform-aws-modules/security-group/aws"
  create              = var.es_create
  version             = "5.1.2"
  name                = "${var.deployment_id}-elastisearch"
  description         = "Elasticsearch security group for Checkmarx One deployment named ${var.deployment_id}"
  vpc_id              = var.vpc_id
  ingress_cidr_blocks = data.aws_vpc.main.cidr_block_associations[*].cidr_block
  ingress_rules       = ["elasticsearch-rest-tcp", "elasticsearch-java-tcp"]
}


output "es_endpoint" {
  value = var.es_create ? aws_elasticsearch_domain.es[0].endpoint : ""
}

output "es_username" {
  value = var.es_create ? var.es_username : ""
}

output "es_password" {
  value     = var.es_create ? var.es_password : ""
  sensitive = true
}