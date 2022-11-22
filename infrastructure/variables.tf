# PROVIDERS
# AWS
variable "aws_region" {
  type        = string
  description = "AWS region to use"
}

# METADATA VARIABLES
variable "deployment_id" {
  description = "the id of the deployment. It's goint to be the EKS cluster name"
  type        = string
  nullable    = false
  validation {
    condition     = (length(var.deployment_id) > 0)
    error_message = "The deployment_id is required."
  }
}

#EKS
variable "environment" {
  description = "the name of the environment. for example: production / dev / stanging/ QA and etc."
  type        = string
  validation {
    condition     = (length(var.environment) > 0)
    error_message = "The environment variable is required."
  }
  nullable = false
}

variable "owner" {
  description = "the name of the deployment owner. for example: ast-team"
  type        = string
  validation {
    condition     = (length(var.owner) > 0)
    error_message = "The owner variable is required."
  }
  nullable = false
}

variable "eks_cluster_version" {
  description = "EKS Kubernetes version to be used"
  type        = string
  default     = "1.21"
  nullable    = false
}

variable "coredns" {
  type = object({
    resolve_conflicts = string
    version           = string
  })
}

variable "kubeproxy" {
  type = object({
    resolve_conflicts = string
    version           = string
  })
}

variable "vpccni" {
  type = object({
    resolve_conflicts = string
    version           = string
  })
}

# S3
variable "s3_retention_period" {
  description = "S3 Retention Period"
  type        = string
  default     = "90"
}

# NODEGROUPS
variable "ast_nodes" {
  type = object({
    instance_types  = list(string)
    min_size        = number
    desired_size    = number
    max_size        = number
    capacity_type   = string
    disk_size_gib   = number
    disk_iops       = number
    disk_throughput = number
    device_name     = string
    volume_type     = string
    name            = string
  })
  default = {
    name            = "ast"
    min_size        = 3
    desired_size    = 3
    max_size        = 10
    instance_types  = ["c5.2xlarge"]
    disk_size_gib   = 50
    disk_iops       = 3000 # this should be the default
    disk_throughput = 125  # this should be the default
    capacity_type   = "ON_DEMAND"
    device_name     = "/dev/xvda"
    volume_type     = "gp3"
  }
  validation {
    condition     = var.ast_nodes.desired_size >= 1
    error_message = "You must have at least 1 instance in this node group."
  }
  validation {
    condition     = var.ast_nodes.disk_size_gib >= 20
    error_message = "You must provide at least 20 GiB per node."
  }

  validation {
    condition     = alltrue([var.ast_nodes.disk_iops >= 3000, var.ast_nodes.disk_iops <= 16000])
    error_message = "You must provide a value between 3000 and 16000."
  }

  validation {
    condition     = alltrue([var.ast_nodes.disk_throughput >= 125, var.ast_nodes.disk_throughput <= 1000])
    error_message = "You must provide a value between 125 and 1000."
  }
  description = "Configuration for the AST nodes"
}

variable "sast_nodes" {
  type = object({
    instance_types  = list(string)
    min_size        = number
    desired_size    = number
    max_size        = number
    capacity_type   = string
    disk_size_gib   = number
    disk_iops       = number
    disk_throughput = number
    device_name     = string
    volume_type     = string
    key             = string
    value           = string
    effect          = string
    name            = string
    label_name      = string
    label_value     = string
  })

  default = {
    name            = "sast-eng"
    min_size        = 1
    desired_size    = 1
    max_size        = 100
    instance_types  = ["c6i.2xlarge"]
    disk_size_gib   = 50
    disk_iops       = 3000 # this should be the default
    disk_throughput = 125  # this should be the default
    capacity_type   = "ON_DEMAND"
    device_name     = "/dev/xvda"
    volume_type     = "gp3"
    key             = "sast-engine"
    value           = "true"
    effect          = "NO_SCHEDULE"
    label_name      = "sast-engine"
    label_value     = "true"
  }
  validation {
    condition     = var.sast_nodes.disk_size_gib >= 8
    error_message = "You must provide at least 8 GiB per node."
  }
  validation {
    condition     = alltrue([var.sast_nodes.disk_iops >= 3000, var.sast_nodes.disk_iops <= 16000])
    error_message = "You must provide a value between 3000 and 16000."
  }

  validation {
    condition     = alltrue([var.sast_nodes.disk_throughput >= 125, var.sast_nodes.disk_throughput <= 1000])
    error_message = "You must provide a value between 125 and 1000."
  }
  description = "Configuration for the SAST nodes"
}

# -------------------

variable "sast_nodes_medium" {
  type = object({
    instance_types  = list(string)
    min_size        = number
    desired_size    = number
    max_size        = number
    capacity_type   = string
    disk_size_gib   = number
    disk_iops       = number
    disk_throughput = number
    device_name     = string
    volume_type     = string
    key             = string
    value           = string
    effect          = string
    name            = string
    label_name      = string
    label_value     = string
  })

  default = {
    name            = "sast-eng-m"
    min_size        = 0
    desired_size    = 0
    max_size        = 100
    instance_types  = ["m5.2xlarge"]
    disk_size_gib   = 50
    disk_iops       = 3000 # this should be the default
    disk_throughput = 125  # this should be the default
    capacity_type   = "ON_DEMAND"
    device_name     = "/dev/xvda"
    volume_type     = "gp3"
    key             = "sast-engine-medium"
    value           = "true"
    effect          = "NO_SCHEDULE"
    label_name      = "sast-engine-medium"
    label_value     = "true"
  }
  validation {
    condition     = var.sast_nodes_medium.disk_size_gib >= 8
    error_message = "You must provide at least 8 GiB per node."
  }
  validation {
    condition     = alltrue([var.sast_nodes_medium.disk_iops >= 3000, var.sast_nodes_medium.disk_iops <= 16000])
    error_message = "You must provide a value between 3000 and 16000."
  }

  validation {
    condition     = alltrue([var.sast_nodes_medium.disk_throughput >= 125, var.sast_nodes_medium.disk_throughput <= 1000])
    error_message = "You must provide a value between 125 and 1000."
  }
  description = "Configuration for the SAST nodes"
}

# -------------------

variable "sast_nodes_large" {
  type = object({
    instance_types  = list(string)
    min_size        = number
    desired_size    = number
    max_size        = number
    capacity_type   = string
    disk_size_gib   = number
    disk_iops       = number
    disk_throughput = number
    device_name     = string
    volume_type     = string
    key             = string
    value           = string
    effect          = string
    name            = string
    label_name      = string
    label_value     = string
  })

  default = {
    name            = "sast-eng-l"
    min_size        = 0
    desired_size    = 0
    max_size        = 300
    instance_types  = ["r6i.xlarge"]
    disk_size_gib   = 50
    disk_iops       = 3000 # this should be the default
    disk_throughput = 125  # this should be the default
    capacity_type   = "ON_DEMAND"
    device_name     = "/dev/xvda"
    volume_type     = "gp3"
    key             = "sast-engine-large"
    value           = "true"
    effect          = "NO_SCHEDULE"
    label_name      = "sast-engine-large"
    label_value     = "true"
  }
  validation {
    condition     = var.sast_nodes_large.disk_size_gib >= 8
    error_message = "You must provide at least 8 GiB per node."
  }
  validation {
    condition     = alltrue([var.sast_nodes_large.disk_iops >= 3000, var.sast_nodes_large.disk_iops <= 16000])
    error_message = "You must provide a value between 3000 and 16000."
  }

  validation {
    condition     = alltrue([var.sast_nodes_large.disk_throughput >= 125, var.sast_nodes_large.disk_throughput <= 1000])
    error_message = "You must provide a value between 125 and 1000."
  }
  description = "Configuration for the SAST nodes"
}

variable "sast_nodes_extra_large" {
  type = object({
    instance_types  = list(string)
    min_size        = number
    desired_size    = number
    max_size        = number
    capacity_type   = string
    disk_size_gib   = number
    disk_iops       = number
    disk_throughput = number
    device_name     = string
    volume_type     = string
    key             = string
    value           = string
    effect          = string
    name            = string
    label_name      = string
    label_value     = string
  })

  default = {
    name            = "sast-eng-xl"
    min_size        = 0
    desired_size    = 0
    max_size        = 100
    instance_types  = ["r6i.2xlarge"]
    disk_size_gib   = 50
    disk_iops       = 3000 # this should be the default
    disk_throughput = 125  # this should be the default
    capacity_type   = "ON_DEMAND"
    device_name     = "/dev/xvda"
    volume_type     = "gp3"
    key             = "sast-engine-extra-large"
    value           = "true"
    effect          = "NO_SCHEDULE"
    label_name      = "sast-engine-extra-large"
    label_value     = "true"
  }
  validation {
    condition     = var.sast_nodes_extra_large.disk_size_gib >= 8
    error_message = "You must provide at least 8 GiB per node."
  }
  validation {
    condition     = alltrue([var.sast_nodes_extra_large.disk_iops >= 3000, var.sast_nodes_extra_large.disk_iops <= 16000])
    error_message = "You must provide a value between 3000 and 16000."
  }

  validation {
    condition     = alltrue([var.sast_nodes_extra_large.disk_throughput >= 125, var.sast_nodes_extra_large.disk_throughput <= 1000])
    error_message = "You must provide a value between 125 and 1000."
  }
  description = "Configuration for the SAST nodes"
}

variable "sast_nodes_xxl" {
  type = object({
    instance_types  = list(string)
    min_size        = number
    desired_size    = number
    max_size        = number
    capacity_type   = string
    disk_size_gib   = number
    disk_iops       = number
    disk_throughput = number
    device_name     = string
    volume_type     = string
    key             = string
    value           = string
    effect          = string
    name            = string
    label_name      = string
    label_value     = string
  })

  default = {
    name            = "sast-eng-xxl"
    min_size        = 0
    desired_size    = 0
    max_size        = 50
    instance_types  = ["r6i.4xlarge"]
    disk_size_gib   = 50
    disk_iops       = 3000 # this should be the default
    disk_throughput = 125  # this should be the default
    capacity_type   = "ON_DEMAND"
    device_name     = "/dev/xvda"
    volume_type     = "gp3"
    key             = "sast-engine-xxl"
    value           = "true"
    effect          = "NO_SCHEDULE"
    label_name      = "sast-engine-xxl"
    label_value     = "true"
  }
  validation {
    condition     = var.sast_nodes_xxl.disk_size_gib >= 8
    error_message = "You must provide at least 8 GiB per node."
  }
  validation {
    condition     = alltrue([var.sast_nodes_xxl.disk_iops >= 3000, var.sast_nodes_xxl.disk_iops <= 16000])
    error_message = "You must provide a value between 3000 and 16000."
  }

  validation {
    condition     = alltrue([var.sast_nodes_xxl.disk_throughput >= 125, var.sast_nodes_xxl.disk_throughput <= 1000])
    error_message = "You must provide a value between 125 and 1000."
  }
  description = "Configuration for the SAST nodes"
}

variable "kics_nodes" {
  type = object({
    name            = string
    instance_types  = list(string)
    min_size        = number
    desired_size    = number
    max_size        = number
    capacity_type   = string
    disk_size_gib   = number
    disk_iops       = number
    disk_throughput = number
    device_name     = string
    volume_type     = string
    key             = string
    value           = string
    effect          = string
    label_name      = string
    label_value     = string
  })

  default = {
    name            = "kics"
    min_size        = 1
    desired_size    = 1
    max_size        = 10
    instance_types  = ["c5.2xlarge"]
    disk_size_gib   = 50
    disk_iops       = 3000 # this should be the default
    disk_throughput = 125  # this should be the default
    capacity_type   = "ON_DEMAND"
    device_name     = "/dev/xvda"
    volume_type     = "gp3"
    key             = "kics-engine"
    value           = "true"
    effect          = "NO_SCHEDULE"
    label_name      = "kics-engine"
    label_value     = "true"
  }
  validation {
    condition     = var.kics_nodes.disk_size_gib >= 8
    error_message = "You must provide at least 8 GiB per node."
  }
  validation {
    condition     = alltrue([var.kics_nodes.disk_iops >= 3000, var.kics_nodes.disk_iops <= 16000])
    error_message = "You must provide a value between 3000 and 16000."
  }

  validation {
    condition     = alltrue([var.kics_nodes.disk_throughput >= 125, var.kics_nodes.disk_throughput <= 1000])
    error_message = "You must provide a value between 125 and 1000."
  }
  description = "Configuration for the SAST nodes"
}

# MINIO
variable "minio_gateway_nodes" {
  type = object({
    name            = string
    instance_types  = list(string)
    min_size        = number
    desired_size    = number
    max_size        = number
    capacity_type   = string
    disk_size_gib   = number
    disk_iops       = number
    disk_throughput = number
    device_name     = string
    volume_type     = string
    key             = string
    value           = string
    effect          = string
    label_name      = string
    label_value     = string
  })

  default = {
    name            = "minio-gateway"
    min_size        = 1
    desired_size    = 1
    max_size        = 10
    instance_types  = ["c6i.2xlarge"]
    disk_size_gib   = 50
    disk_iops       = 3000 # this should be the default
    disk_throughput = 125  # this should be the default
    capacity_type   = "ON_DEMAND"
    device_name     = "/dev/xvda"
    volume_type     = "gp3"
    key             = "minio-gateway"
    value           = "true"
    effect          = "NO_SCHEDULE"
    label_name      = "minio-gateway"
    label_value     = "true"
  }
  validation {
    condition     = var.minio_gateway_nodes.disk_size_gib >= 8
    error_message = "You must provide at least 8 GiB per node."
  }
  validation {
    condition     = alltrue([var.minio_gateway_nodes.disk_iops >= 3000, var.minio_gateway_nodes.disk_iops <= 16000])
    error_message = "You must provide a value between 3000 and 16000."
  }

  validation {
    condition     = alltrue([var.minio_gateway_nodes.disk_throughput >= 125, var.minio_gateway_nodes.disk_throughput <= 1000])
    error_message = "You must provide a value between 125 and 1000."
  }
  description = "Configuration for the Minio Gateway nodes"
}

# REPOSTORE
variable "repostore_nodes" {
  type = object({
    name            = string
    instance_types  = list(string)
    min_size        = number
    desired_size    = number
    max_size        = number
    capacity_type   = string
    disk_size_gib   = number
    disk_iops       = number
    disk_throughput = number
    device_name     = string
    volume_type     = string
    key             = string
    value           = string
    effect          = string
    label_name      = string
    label_value     = string
  })

  default = {
    name            = "repostore"
    min_size        = 1
    desired_size    = 1
    max_size        = 10
    instance_types  = ["c5.2xlarge"]
    disk_size_gib   = 50
    disk_iops       = 3000 # this should be the default
    disk_throughput = 125  # this should be the default
    capacity_type   = "ON_DEMAND"
    device_name     = "/dev/xvda"
    volume_type     = "gp3"
    key             = "repostore"
    value           = "true"
    effect          = "NO_SCHEDULE"
    label_name      = "repostore"
    label_value     = "true"
  }
  validation {
    condition     = var.repostore_nodes.disk_size_gib >= 8
    error_message = "You must provide at least 8 GiB per node."
  }
  validation {
    condition     = alltrue([var.repostore_nodes.disk_iops >= 3000, var.repostore_nodes.disk_iops <= 16000])
    error_message = "You must provide a value between 3000 and 16000."
  }

  validation {
    condition     = alltrue([var.repostore_nodes.disk_throughput >= 125, var.repostore_nodes.disk_throughput <= 1000])
    error_message = "You must provide a value between 125 and 1000."
  }
  description = "Configuration for the Minio Gateway nodes"
}

#RDS
variable "database_name" {
  type = string
  validation {
    condition     = can(regex("^(?:[a-z]|[a-z][a-z0-9]+)$", var.database_name))
    error_message = "The database_name is not valid."
  }
  sensitive   = true
  description = "Name of the database"
}

variable "database_username" {
  type = string
  validation {
    condition     = var.database_username != ""
    error_message = "The database_username is not valid."
  }
  sensitive   = true
  description = "Username of the database"
}

variable "database_password" {
  type = string
  validation {
    condition     = var.database_password != ""
    error_message = "The database_password is not valid."
  }
  sensitive   = true
  description = "Password of the database"
}

variable "postgres_nodes" {
  type = object({
    create              = bool
    auto_scaling_enable = bool
    instance_type       = string
    count               = number
    max_count           = number
  })
  validation {
    condition     = (var.postgres_nodes.create == false) || (var.postgres_nodes.create == true && var.postgres_nodes.instance_type != "" && var.postgres_nodes.count > 0)
    error_message = "The field instance_type cannot be empty and the number of db nodes must be greater than zero."
  }
  description = "Configuration for the Aurora Postgres DB nodes"
}

# REDIS
variable "redis_auth_token" {
  type        = string
  sensitive   = true
  description = "Auth token for Elasticache Redis DB"
  default     = ""
}

variable "redis_nodes" {
  type = object({
    create             = bool
    instance_type      = string
    replicas_per_shard = number
    number_of_shards   = number
  })
  validation {
    condition     = (var.redis_nodes.create == false) || (var.redis_nodes.create == true && var.redis_nodes.instance_type != "" && var.redis_nodes.number_of_shards > 0)
    error_message = "The field instance_type cannot be empty and the number of db shards must be greater than zero."
  }
  description = "Configuration for the Elasticache Redis DB nodes"
}

# VPC
variable "vpc" {
  type = object({
    create                    = bool
    nat_per_az                = bool
    single_nat                = bool
    existing_vpc_id           = string
    existing_subnet_ids       = list(string)
    existing_db_subnets_group = string
    existing_db_subnets       = list(string)
  })
  validation {
    condition     = (var.vpc.create == true) || ((length(var.vpc.existing_subnet_ids) > 0) && (length(var.vpc.existing_vpc_id) > 0) && var.vpc.existing_db_subnets_group != "" && (length(var.vpc.existing_db_subnets) > 0))
    error_message = "You must create a VPC or provide existing VPC information."
  }
  description = "Configuration for the VPC. If you want to use your own VPC you must follow AWS instructions for VPC-EKS"
}

variable "vpc_cidr" {
  description = "the main cidr of the vpc"
  type        = string
  default     = "10.1.0.0/16"
  validation {
    condition     = can(regex("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\\/([0-9]|[1-2][0-9]|3[0-2]))?$", var.vpc_cidr))
    error_message = "Valid cidr is required. The subnet masking must be /21 ."
  }
  nullable = false
}

# Security groups
variable "sig" {
  type = object({
    create                     = bool
    existing_sig_k8s_to_dbs_id = string
  })
  validation {
    condition     = (var.sig.create == true) || ((length(var.sig.existing_sig_k8s_to_dbs_id) > 0))
    error_message = "You must create a Security groups or provide existing VPC information."
  }
  description = "Configuration for the Security groups."
}

# KMS
variable "kms" {
  type = object({
    create           = bool
    existing_kms_arn = string
  })
  validation {
    condition     = (var.kms.create == true) || (length(var.kms.existing_kms_arn) > 0)
    error_message = "You must create a KMS or provide existing KMS."
  }
  description = "Configuration for the KMS."
}


# S3
variable "enable_s3_bucket_versioning" {
  type        = bool
  description = "Enable S3 Bucket versioning"
  default     = false
}