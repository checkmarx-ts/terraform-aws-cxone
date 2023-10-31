variable "deployment_id" {
  description = "The id of the deployment. Will be used to name resources like EKS cluster, etc."
  type        = string
  nullable    = false
  validation {
    condition     = (length(var.deployment_id) > 0)
    error_message = "The deployment_id is required."
  }
}

variable "environment" {
  description = "The name of the environment. For example: production, staging, dev, etc."
  type        = string
  validation {
    condition     = (length(var.environment) > 0)
    error_message = "The environment variable is required."
  }
  nullable = false
}

variable "ast_tenant_name" {
  description = "The tenant name, that must match exactly the tenant name in your Checkmarx One license."
  type        = string
  nullable    = false
}

variable "owner" {
  description = "The name of the deployment owner. for example: you@example.com"
  type        = string
  validation {
    condition     = (length(var.owner) > 0)
    error_message = "The owner variable is required."
  }
  nullable = false
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC. Must be a /16 network"
  type        = string
  validation {
    condition     = (cidrnetmask(var.vpc_cidr) == "255.255.0.0")
    error_message = "vpc_cidr must be a /16 network with netmask 255.255.0.0 e.g. 10.1.0.0/16"
  }
}

variable "administrator_iam_role_arn" {
  description = "The IAM role for the administrator group that will allow system administration (e.g. EKS master)"
  type        = string
  nullable    = false
}