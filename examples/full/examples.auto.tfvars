
#******************************************************************************
#   Base Infrastructure Configuration
#******************************************************************************
vpc_cidr                = "10.77.0.0/16"
secondary_vpc_cidr      = "100.64.0.0/16"
interface_vpc_endpoints = ["ec2", "ec2messages", "ssm", "ssmmessages", "ecr.api", "ecr.dkr", "kms", "logs", "sts", "elasticloadbalancing", "autoscaling"]
create_s3_endpoint      = true
route_53_hosted_zone_id = "<enter your hosted zone id e.g. Z0962235AVF65523G11OI"
fqdn                    = "example.checkmarx-ps.com"
deployment_id           = "cxone-dev"
ec2_key_name            = "<enter your ec2 key>"

#******************************************************************************
#   S3 Configuration
#******************************************************************************
object_storage_endpoint   = "<enter your s3 region e.g. s3.us-west-2.amazonaws.com>"
object_storage_access_key = "<enter your AWS Access Key for the IAM user that connects to S3 buckets>"
object_storage_secret_key = "<enter your AWS Secret Key for the IAM user that connects to S3 buckets>"

#******************************************************************************
#   Kots & Installation Configuration
#******************************************************************************
kots_admin_email     = "<email address of the CxOne first administrator user>"
kots_release_channel = "beta"
kots_cxone_version   = "3.10.5"
kots_license_file    = "<path to your Checkmarx One license.yml file>"

#******************************************************************************
# terraform-aws-cxone module pass thru variables
#******************************************************************************
eks_create                               = true
eks_create_cluster_autoscaler_irsa       = true
eks_create_external_dns_irsa             = true
eks_create_load_balancer_controller_irsa = true
eks_create_karpenter                     = false
eks_version                              = "1.27"
coredns_version                          = "v1.10.1-eksbuild.7"
kube_proxy_version                       = "v1.27.10-eksbuild.2"
vpc_cni_version                          = "v1.17.1-eksbuild.1"
aws_ebs_csi_driver_version               = "v1.27.0-eksbuild.1"
eks_private_endpoint_enabled             = true
eks_public_endpoint_enabled              = true
eks_cluster_endpoint_public_access_cidrs = ["0.0.0.0/0"]
enable_cluster_creator_admin_permissions = true
eks_node_additional_security_group_ids   = []
# Uncomment the eks_administrator_principals to specify additional principal ARNs that should have admin
# access to EKS.
# eks_administrator_principals = [
#   {
#     name          = "YourName1"
#     principal_arn = "arn:aws:iam::1234567890:role/aws-reserved/sso.amazonaws.com/us-east-1/YourRoleName1"
#   },
#   {
#     name          = "YourName2"
#     principal_arn = "arn:aws:iam::1234567890:role/aws-reserved/sso.amazonaws.com/us-east-1/YourName2"
#   }
# ]
launch_template_tags = {
  CostCenter     = "12345"
  "Custom:owner" = "foobar"
}
eks_node_groups = [{
  name           = "ast-app"
  min_size       = 3
  desired_size   = 3
  max_size       = 9
  instance_types = ["c5.4xlarge"]
  },
  {
    name           = "sast-engine"
    min_size       = 0
    desired_size   = 0
    max_size       = 100
    instance_types = ["m5.2xlarge"]
    labels = {
      "sast-engine" = "true"
    }
    taints = {
      dedicated = {
        key    = "sast-engine"
        value  = "true"
        effect = "NO_SCHEDULE"
      }
    }
  },
  {
    name           = "sast-engine-large"
    min_size       = 0
    desired_size   = 0
    max_size       = 100
    instance_types = ["m5.4xlarge"]
    labels = {
      "sast-engine-large" = "true"
    }
    taints = {
      dedicated = {
        key    = "sast-engine-large"
        value  = "true"
        effect = "NO_SCHEDULE"
      }
    }
  },
  {
    name           = "sast-engine-extra-large"
    min_size       = 0
    desired_size   = 0
    max_size       = 100
    instance_types = ["r5.2xlarge"]
    labels = {
      "sast-engine-extra-large" = "true"
    }
    taints = {
      dedicated = {
        key    = "sast-engine-extra-large"
        value  = "true"
        effect = "NO_SCHEDULE"
      }
    }
  },
  {
    name           = "sast-engine-xxl"
    min_size       = 0
    desired_size   = 0
    max_size       = 100
    instance_types = ["r5.4xlarge"]
    labels = {
      "sast-engine-xxl" = "true"
    }
    taints = {
      dedicated = {
        key    = "sast-engine-xxl"
        value  = "true"
        effect = "NO_SCHEDULE"
      }
    }
  },
  {
    name           = "kics-engine"
    min_size       = 1
    desired_size   = 1
    max_size       = 100
    instance_types = ["c5.2xlarge"]
    labels = {
      "kics-engine" = "true"
    }
    taints = {
      dedicated = {
        key    = "kics-engine"
        value  = "true"
        effect = "NO_SCHEDULE"
      }
    }
  },
  {
    name           = "repostore"
    min_size       = 1
    desired_size   = 1
    max_size       = 100
    instance_types = ["c5.2xlarge"]
    labels = {
      "repostore" = "true"
    }
    taints = {
      dedicated = {
        key    = "repostore"
        value  = "true"
        effect = "NO_SCHEDULE"
      }
    }
  },
  {
    name           = "sca-source-resolver"
    min_size       = 1
    desired_size   = 1
    max_size       = 100
    instance_types = ["m5.2xlarge"]
    labels = {
      "service" = "sca-source-resolver"
    }
    taints = {
      dedicated = {
        key    = "service"
        value  = "sca-source-resolver"
        effect = "NO_SCHEDULE"
      }
    }
  }
]


#******************************************************************************
# RDS Configuration
#******************************************************************************
db_engine_version              = "13.12"
db_allow_major_version_upgrade = true
db_auto_minor_version_upgrade  = true
db_apply_immediately           = true
db_deletion_protection         = false
db_skip_final_snapshot         = true
db_final_snapshot_identifier   = "your-final-snapshot-id"
db_snapshot_identifer          = null
db_instance_class              = "db.serverless" # "db.r6g.large"
db_monitoring_interval         = "10"
# When enabling autoscaling, you may need to edit and save the autoscaling policy (no updates needed)
# to work around the issue described here: https://github.com/terraform-aws-modules/terraform-aws-rds-aurora/issues/432
db_autoscaling_enabled                      = false # Autoscaling not supported by Checkmarx One Single Tenant, yet.
db_autoscaling_min_capacity                 = 1
db_autoscaling_max_capacity                 = 3
db_autoscaling_target_cpu                   = 70
db_autoscaling_scale_out_cooldown           = 300
db_autoscaling_scale_in_cooldown            = 300
db_port                                     = "5432"
db_create_rds_proxy                         = false #true
db_create                                   = true
db_performance_insights_enabled             = true
db_performance_insights_retention_period    = 7
db_cluster_db_instance_parameter_group_name = "aurora-postgresql13-cluster"
# Set individual instance properties. Reference https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/rds_cluster_instance
db_instances = {
  writer = {}
  replica1 = {
    promotion_tier = 0
  }
}
db_serverlessv2_scaling_configuration = {
  min_capacity = 0.5
  max_capacity = 8
}


#******************************************************************************
# Elasticache Configuration
#******************************************************************************
ec_create                         = true
ec_enable_serverless              = false # Serverless EC is not supported by Checkmarx One, yet.
ec_serverless_max_storage         = 5
ec_serverless_max_ecpu_per_second = 5000
ec_engine_version                 = "6.x"                         # "6.x"
ec_parameter_group_name           = "default.redis6.x.cluster.on" # "default.redis6.x.cluster.on"
ec_automatic_failover_enabled     = true
ec_multi_az_enabled               = true
ec_node_type                      = "cache.r7g.large" # Production: cache.r7g.xlarge, Dev/Test: cache.t4g.medium, Demo: cache.t4g.micro. Note: Not all regions have r7 generation instances.
ec_number_of_shards               = 1                 # Production 3, Dev/Test: 1, Demo: 1
ec_replicas_per_shard             = 2                 # Production 2, Dev/Test: 1, Demo: 0
ec_auto_minor_version_upgrade     = false

#******************************************************************************
# Elasticsearch Configuration
#******************************************************************************
es_create              = true
es_instance_count      = 2
es_instance_type       = "r6g.large.elasticsearch"
es_volume_size         = 50
es_tls_security_policy = "Policy-Min-TLS-1-2-2019-07"
es_username            = "ast"
