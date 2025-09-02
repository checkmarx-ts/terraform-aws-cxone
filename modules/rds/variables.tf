variable "deployment_id" {
  description = "The id of the deployment. Will be used to name resources like EKS cluster, etc."
  type        = string
  nullable    = false
  validation {
    condition     = (length(var.deployment_id) > 0)
    error_message = "The deployment_id is required."
  }
}

variable "vpc_id" {
  type        = string
  nullable    = false
  description = "The VPC ID to deploy into."
}

variable "db_subnet_group_name" {
  type        = string
  nullable    = false
  description = "The db subnet group name to deploy into."
}

variable "security_group_ids" {
  description = "The id(s) of the security group for the instance."
  type        = list(string)
  nullable    = false
}


variable "engine_version" {
  description = "The aurora postgres engine version."
  type        = string
  default     = "13.12"
}

variable "db_instances" {
  type        = map(any)
  description = "The db instance configuration"
  default = {
    1 = {
      instance_class      = "db.r6g.xlarge"
      publicly_accessible = false
    }
  }
}

variable "postgres_nodes" {
  description = "Configuration for the Aurora Postgres DB nodes"
  type = object({
    auto_scaling_enable = bool
    instance_type       = string
    count               = number
    max_count           = number
  })
  validation {
    condition     = (var.postgres_nodes.instance_type != "" && var.postgres_nodes.count > 0)
    error_message = "The field instance_type cannot be empty and the number of db nodes must be greater than zero."
  }

  default = {
    auto_scaling_enable = false
    instance_type       = "db.r6g.xlarge"
    count               = 1
    max_count           = 1
  }

}

variable "kms_key_arn" {
  description = "The ARN of the KMS key to use for encryption."
  type        = string
  nullable    = false
}



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

variable "cluster_monitoring_interval" {
  default     = 0
  type        = number
  description = "The interval, in seconds, between points when Enhanced Monitoring metrics are collected for instances. Set to `0` to disable. Default is `0`"
}

variable "monitoring_role_arn" {
  type        = string
  description = "The IAM Role ARN to use for enhanced monitoring"
  default     = null

}

variable "cloudwatch_log_group_retention_in_days" {
  type    = number
  default = 90
  validation {
    condition     = contains([0, 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653], var.cloudwatch_log_group_retention_in_days)
    error_message = "cloudwatch_log_group_retention_in_days must be one of the allowed values: 0,1,3,5,7,14,30,60,90,120,150,180,365,400,545,731,1096,1827,2192,2557,2922,3288,3653."
  }
}

variable "enabled_cloudwatch_logs_exports" {
  type        = list(string)
  description = "Set of log types to export to cloudwatch. If omitted, no logs will be exported. The following log types are supported: `audit`, `error`, `general`, `slowquery`, `postgresql`"
  default     = ["audit", "error", "general", "slowquery", "postgresql"]
}

variable "cloudwatch_log_group_skip_destroy" {
  description = "Set to true if you do not wish the log group (and any logs it may contain) to be deleted at destroy time, and instead just remove the log group from the Terraform state"
  type        = bool
  default     = false
}

variable "create_cloudwatch_log_group" {
  description = "Enable manual creation of cloudwatch log groups"
  type        = bool
  default     = true
}

variable "cloudwatch_log_group_kms_key_id" {
  type    = string
  default = null
}

variable "cloudwatch_log_group_class" {
  type    = string
  default = "STANDARD"

  validation {
    condition     = contains(["STANDARD", "INFREQUENT_ACCESS"], var.cloudwatch_log_group_class)
    error_message = "cloudwatch_log_group_class must be one of: STANDARD or INFREQUENT_ACCESS."
  }
}



