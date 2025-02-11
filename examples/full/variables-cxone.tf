# variables-cxone.tf contains pass thru variables defined by terraform-aws-cxone module.
# The variable definitions are duplicated here so that the example project can be used
# to control the module configuration.


#******************************************************************************
#   General Configuration
#******************************************************************************

variable "deployment_id" {
  description = "The id of the deployment. Will be used to name resources like EKS cluster, etc."
  type        = string
  nullable    = false
  validation {
    condition     = (length(var.deployment_id) >= 3)
    error_message = "The deployment_id must be greater than 3 characters."
  }
}

variable "cxone_namespace" {
  description = "The kubernetes namespace in which to deploy the CxOne application."
  type        = string
  default     = "ast"
}

# variable "kms_key_arn" {
#   type        = string
#   description = "The ARN of the KMS key to use for encryption in AWS services"
# }

# variable "vpc_id" {
#   description = "The id of the vpc deploying into."
#   type        = string
# }


#******************************************************************************
#   S3 Configuration
#******************************************************************************

variable "s3_retention_period" {
  description = "The retention period, in days, to retain s3 objects."
  type        = string
  default     = "90"
}

# variable "s3_allowed_origins" {
#   description = "The allowed orgins for S3 CORS rules."
#   type        = list(string)
#   nullable    = false
# }

#******************************************************************************
#   EKS Configuration
#******************************************************************************
variable "eks_create" {
  type        = bool
  description = "Enables the EKS resource creation"
  default     = true
}

# variable "eks_subnets" {
#   description = "The subnets to deploy EKS into."
#   type        = list(string)
# }

variable "create_node_s3_iam_role" {
  type        = bool
  default     = false
  description = "Attach a policy to EKS nodes to access S3 buckets."
}

variable "eks_enable_externalsnat" {
  type        = bool
  description = "Enables [External SNAT](https://docs.aws.amazon.com/eks/latest/userguide/external-snat.html) for the EKS VPC CNI. When true, the EKS pods must have a route to a NAT Gateway for outbound communication."
  default     = false
}

variable "eks_enable_custom_networking" {
  type        = bool
  description = "Enables custom networking for the EKS VPC CNI. When true, custom networking is enabled with `ENI_CONFIG_LABEL_DEF` = `topology.kubernetes.io/zone` and ENIConfig resources must be created."
  default     = false
}

variable "eks_enable_fargate" {
  type        = bool
  description = "Enables Fargate profiles for the karpenter and kube-system namespaces."
  default     = false
}

variable "eks_create_cluster_autoscaler_irsa" {
  type        = bool
  description = "Enables creation of cluster autoscaler IAM role."
  default     = true
}

variable "eks_create_external_dns_irsa" {
  type        = bool
  description = "Enables creation of external dns IAM role."
  default     = true
}

variable "eks_create_load_balancer_controller_irsa" {
  type        = bool
  description = "Enables creation of load balancer controller IAM role."
  default     = true
}

variable "eks_create_karpenter" {
  type        = bool
  description = "Enables creation of Karpenter resources."
  default     = false
}

variable "eks_version" {
  type        = string
  description = "The version of the EKS Cluster (e.g. 1.27)"
  default     = "1.30"
}

variable "coredns_version" {
  type        = string
  description = "The version of the EKS Core DNS Addon. Reference https://docs.aws.amazon.com/eks/latest/userguide/managing-coredns.html."
  default     = "v1.11.4-eksbuild.2"
}

variable "kube_proxy_version" {
  type        = string
  description = "The version of the EKS Kube Proxy Addon. Reference https://docs.aws.amazon.com/eks/latest/userguide/managing-kube-proxy.html#kube-proxy-versions."
  default     = "v1.30.7-eksbuild.2"
}

variable "vpc_cni_version" {
  type        = string
  description = "The version of the EKS VPC CNI Addon. Reference https://docs.aws.amazon.com/eks/latest/userguide/managing-vpc-cni.html."
  default     = "v1.19.2-eksbuild.1"
}

variable "aws_ebs_csi_driver_version" {
  type        = string
  description = "The version of the EKS EBS CSI Addon. Reference https://github.com/kubernetes-sigs/aws-ebs-csi-driver/?tab=readme-ov-file#compatibility."
  default     = "v1.39.0-eksbuild.1"
}

variable "eks_private_endpoint_enabled" {
  type        = bool
  description = "Enables the EKS VPC private endpoint."
  default     = true
}

variable "eks_public_endpoint_enabled" {
  type        = bool
  description = "Enables the EKS public endpoint."
  default     = false
}

variable "eks_cluster_endpoint_public_access_cidrs" {
  type        = list(string)
  description = " List of CIDR blocks which can access the Amazon EKS public API server endpoint"
  default     = ["0.0.0.0/0"]
}

variable "eks_node_additional_security_group_ids" {
  description = "Additional security group ids to attach to EKS nodes."
  type        = list(string)
  default     = []
}

variable "eks_post_bootstrap_user_data" {
  type        = string
  description = "User data to insert after bootstrapping script."
  default     = ""
}

variable "eks_pre_bootstrap_user_data" {
  type        = string
  description = "User data to insert before bootstrapping script."
  default     = ""
}

variable "aws_cloudwatch_observability_version" {
  type        = string
  description = "The version of the AWS Cloudwatch Observability Addon. Specify a version to enable the addon, or leave null to disable the addon."
  default     = null
}

variable "launch_template_tags" {
  type        = map(string)
  description = "Tags to associate with launch templates for node groups"
  default     = null
}

variable "enable_cluster_creator_admin_permissions" {
  type        = bool
  description = "Enables the identity used to create the EKS cluster to have administrator access to that EKS cluster. When enabled, do not specify the same principal arn for eks_administrator_principals."
  default     = true
}

variable "eks_administrator_principals" {
  type = list(object({
    name          = string
    principal_arn = string
  }))
  description = "The ARNs of the IAM roles for administrator access to EKS."
  default     = []
}

variable "ec2_key_name" {
  description = "The name of the EC2 key pair to access servers."
  type        = string
  default     = null
}


variable "eks_node_groups" {
  type = list(object({
    name            = string
    min_size        = string
    desired_size    = string
    max_size        = string
    volume_type     = optional(string, "gp3")
    disk_size       = optional(number, 225)
    disk_iops       = optional(number, 3000)
    disk_throughput = optional(number, 125)
    device_name     = optional(string, "/dev/xvda")
    instance_types  = list(string)
    capacity_type   = optional(string, "ON_DEMAND")
    labels          = optional(map(string), {})
    taints          = optional(map(object({ key = string, value = string, effect = string })), {})
  }))
  default = [{
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
      min_size       = 0
      desired_size   = 0
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
}

#******************************************************************************
#   RDS Configuration
#******************************************************************************

variable "db_engine_version" {
  description = "The aurora postgres engine version."
  type        = string
  default     = "13.8"
}


# variable "db_subnets" {
#   description = "The subnets to deploy RDS into."
#   type        = list(string)
# }


variable "db_allow_major_version_upgrade" {
  description = "Allows major version upgrades."
  type        = bool
  default     = false
}

variable "db_auto_minor_version_upgrade" {
  description = "Automatically upgrade to latest minor version in maintenance window."
  type        = bool
  default     = false
}

variable "db_instance_class" {
  description = "The aurora postgres instance class."
  type        = string
  default     = "db.r6g.xlarge"
}

variable "db_monitoring_interval" {
  description = "The aurora postgres engine version."
  type        = string
  default     = "10"
}

variable "db_autoscaling_enabled" {
  description = "Enables autoscaling of the aurora database."
  type        = bool
  default     = true
}

variable "db_autoscaling_min_capacity" {
  description = "The minimum number of replicas via autoscaling."
  type        = string
  default     = "1"
}

variable "db_autoscaling_max_capacity" {
  description = "The maximum number of replicas via autoscaling."
  type        = string
  default     = "3"
}

variable "db_autoscaling_target_cpu" {
  description = "The CPU utilization for autoscaling target tracking."
  type        = number
  default     = 70
}

variable "db_autoscaling_scale_in_cooldown" {
  description = "The database scale in cooldown period."
  type        = number
  default     = 300
}

variable "db_autoscaling_scale_out_cooldown" {
  description = "The database scale ou cooldown period."
  type        = number
  default     = 300
}

variable "db_snapshot_identifer" {
  description = "The snapshot identifier to restore the database from."
  type        = string
  default     = null
}

variable "db_port" {
  description = "The port on which the DB accepts connections."
  type        = string
  default     = "5432"
}

variable "db_master_user_password" {
  description = "The master user password for RDS. Specify to explicitly set the password otherwise RDS will be allowed to manage it."
  type        = string
  default     = null
}

variable "db_create_rds_proxy" {
  description = "Enables an RDS proxy for the Aurora postgres database."
  type        = bool
  default     = true
}

variable "db_create" {
  description = "Controls creation of the Aurora postgres database."
  type        = bool
  default     = true
}

variable "db_skip_final_snapshot" {
  description = "Enables skipping the final snapshot upon deletion."
  type        = bool
  default     = false
}

variable "db_final_snapshot_identifier" {
  description = "Identifer for a final DB snapshot. Required when db_skip_final_snapshot is false.."
  type        = string
  default     = null
}

variable "db_deletion_protection" {
  description = "Enables deletion protection to avoid accidental database deletion."
  type        = bool
  default     = true
}

variable "db_instances" {
  type        = map(any)
  description = "The DB instance configuration"
  default = {
    writer   = {}
    replica1 = {}
  }
}

variable "db_serverlessv2_scaling_configuration" {
  description = "The serverless v2 scaling minimum and maximum."
  type = object({
    min_capacity = number
    max_capacity = number
  })
  default = {
    min_capacity = 0.5
    max_capacity = 32
  }
}

variable "db_performance_insights_enabled" {
  type        = bool
  default     = true
  description = "Enables database performance insights."
}

variable "db_performance_insights_retention_period" {
  type        = number
  default     = 7
  description = "Number of days to retain performance insights data. Free tier: 7 days."
}

variable "db_cluster_db_instance_parameter_group_name" {
  type        = string
  default     = null
  description = "The name of the DB Cluster parameter group to use."
}

variable "db_apply_immediately" {
  type        = bool
  default     = false
  description = "Determines if changes will be applied immediately or wait until the next maintenance window."
}

variable "db_backup_retention_period" {
  type        = number
  default     = null
  description = "The number of  days to retain database backups for"
}


#******************************************************************************
#   RDS - Analytics - Configuration
#******************************************************************************

variable "analytics_db_instance_class" {
  description = "The aurora postgres instance class."
  type        = string
  default     = "db.r6g.xlarge"
}

variable "analytics_db_final_snapshot_identifier" {
  description = "Identifer for a final DB snapshot for the analytics database. Required when db_skip_final_snapshot is false.."
  type        = string
  default     = null
}

variable "analytics_db_snapshot_identifer" {
  description = "The snapshot identifier to restore the anatlytics database from."
  type        = string
  default     = null
}

variable "analytics_db_cluster_db_instance_parameter_group_name" {
  type        = string
  default     = null
  description = "The name of the DB Cluster parameter group to use."
}

variable "analytics_db_master_user_password" {
  description = "The master user password for RDS. Specify to explicitly set the password otherwise RDS will be allowed to manage it."
  type        = string
  default     = null
}

variable "analytics_db_instances" {
  type        = map(any)
  description = "The DB instance configuration"
  default = {
    writer   = {}
    replica1 = {}
  }
}

variable "analytics_db_serverlessv2_scaling_configuration" {
  description = "The serverless v2 scaling minimum and maximum."
  type = object({
    min_capacity = number
    max_capacity = number
  })
  default = {
    min_capacity = 0.5
    max_capacity = 32
  }
}




#******************************************************************************
# Elasticache Configuration
#******************************************************************************
variable "ec_create" {
  type        = bool
  default     = true
  description = "Enables the creation of elasticache resources."
}

# variable "ec_subnets" {
#   description = "The subnets to deploy Elasticache into."
#   type        = list(string)
# }

variable "ec_enable_serverless" {
  type        = bool
  default     = false
  description = "Enables the use of elasticache for redis serverless."
}

variable "ec_serverless_max_storage" {
  type        = number
  default     = 5
  description = "The max storage, in GB, for serverless elasticache for redis."
}
variable "ec_serverless_max_ecpu_per_second" {
  type        = number
  default     = 5000
  description = "The max eCPU per second for serverless elasticache for redis."
}

variable "ec_engine_version" {
  type        = string
  description = "The version of the elasticache cluster. Does not apply to serverless."
  default     = "6.x"
}
variable "ec_parameter_group_name" {
  type        = string
  description = "The elasticache parameter group name. Does not apply to serverless."
  default     = "default.redis6.x.cluster.on"
}

variable "ec_node_type" {
  type        = string
  description = "The elasticache redis node type. Does not apply to serverless."
  default     = "cache.m6g.large"
}

variable "ec_number_of_shards" {
  type        = number
  description = "The number of shards for redis. Does not apply to serverless."
  default     = 3
}

variable "ec_replicas_per_shard" {
  type        = number
  description = "The number of replicas per shard for redis. Does not apply to serverless."
  default     = 2
}

variable "ec_auto_minor_version_upgrade" {
  type        = bool
  description = "Enables automatic minor version upgrades. Does not apply to serverless."
  default     = false
}

variable "ec_automatic_failover_enabled" {
  type        = bool
  description = "Enables automatic failover. Does not apply to serverless."
  default     = true
}

variable "ec_multi_az_enabled" {
  type        = bool
  description = "Enables automatic failover. Does not apply to serverless."
  default     = true
}

#******************************************************************************
# Elasticsearch Configuration
#******************************************************************************

variable "es_create" {
  type        = bool
  description = "Enables creation of elasticsearch resources."
  default     = true
}

# variable "es_subnets" {
#   description = "The subnets to deploy Elasticsearch into."
#   type        = list(string)
# }

variable "es_enable_dedicated_master_nodes" {
  default     = false
  type        = bool
  description = "Enable use of dedicated master nodes for the cluster."
}

variable "es_dedicated_master_count" {
  default     = 3
  type        = number
  description = "The number of master nodes to use for the cluster."
}

variable "es_dedicated_master_type" {
  default     = "m7g.large.elasticsearch"
  type        = string
  description = "The instance type of the master nodes."
}

variable "es_instance_type" {
  type        = string
  description = "The instance type for elasticsearch nodes."
  default     = "r6g.large.elasticsearch"
}

variable "es_instance_count" {
  type        = number
  description = "The number of nodes in elasticsearch cluster"
  default     = 2
}

variable "es_volume_size" {
  type        = number
  description = "The size of volumes for nodes in elasticsearch cluster"
  default     = 100
}

variable "es_tls_security_policy" {
  default = "Policy-Min-TLS-1-2-2019-07"
  type    = string
}

variable "es_username" {
  description = "The username for the elasticsearch user"
  type        = string
  default     = "ast"
}

# variable "es_password" {
#   description = "The password for the elasticsearch user"
#   type        = string
#   sensitive   = true
# }

