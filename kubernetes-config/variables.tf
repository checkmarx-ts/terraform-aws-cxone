# BACKEND CONFIG
variable "s3_backend_infra_bucket" {
  type        = string
  description = "S3 name where the infra state is stored"
  default     = ""
  validation {
    condition     = (length(var.s3_backend_infra_bucket) > 0)
    error_message = "The s3_backend_infra_bucket variable is required."
  }
  nullable = false
}

variable "s3_backend_infra_remote_config_key" {
  description = "Path to the infra state file in the S3 Bucket"
  type        = string
  default     = ""
  validation {
    condition     = (length(var.s3_backend_infra_remote_config_key) > 0)
    error_message = "The s3_backend_infra_remote_config_key variable is required."
  }
  nullable = false
}

variable "s3_backend_infra_bucket_region" {
  description = "S3 backend bucket region"
  type        = string
  default     = ""
  validation {
    condition     = (length(var.s3_backend_infra_bucket_region) > 0)
    error_message = "The s3_backend_infra_bucket_region variable is required."
  }
  nullable = false
}

# PROVIDERS
# AWS
variable "aws_region" {
  type        = string
  description = "AWS region to use"
}
variable "aws_profile" {
  description = "The aws profile used to run terraform."
  type        = string
  nullable    = false

  validation {
    condition     = (length(var.aws_profile) > 2)
    error_message = "Must have at least 3 characters length."
  }
}

# METADATA VARIABLES
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

variable "deployment_id" {
  description = "the id of the deployment. if not set will used \"{owner}_{environment}\". must be unique per AWS account"
  type        = string
  nullable    = false
  validation {
    condition     = (length(var.deployment_id) > 0)
    error_message = "The deployment_id is required."
  }
}

# Helm

# external_DNS
variable "hosted_zone_id" {
  description = "Route53 hosted Zone ID"
  type        = string
  default     = ""
  nullable    = false
}
