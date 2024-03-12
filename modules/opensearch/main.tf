

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

resource "aws_elasticsearch_domain" "es" {
  domain_name           = var.deployment_id
  elasticsearch_version = "7.10"

  cluster_config {
    instance_type          = var.instance_type
    instance_count         = var.instance_count
    zone_awareness_enabled = true
    zone_awareness_config {
      availability_zone_count = min(length(var.subnet_ids), var.instance_count)
    }
  }

  #   auto_tune_options {
  #     desired_state = "ENABLED"
  #     maintenance_schedule {
  #       start_at = timeadd(plantimestamp(), "24h")
  #       duration {
  #         value = 4
  #         unit  = "HOURS"

  #       }
  #       cron_expression_for_recurrence = "0 0 * * *" # daily
  #     }
  #     rollback_on_disable = "DEFAULT_ROLLBACK"
  #   }


  vpc_options {
    subnet_ids         = var.subnet_ids
    security_group_ids = var.security_group_ids
  }

  snapshot_options {
    automated_snapshot_start_hour = 06
  }

  ebs_options {
    ebs_enabled = true
    volume_type = "gp3"
    volume_size = var.volume_size
    throughput  = 125
    iops        = 3000
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
    master_user_options {
      master_user_name     = "ast"
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

  tags = {
    Domain = var.deployment_id
  }

}
