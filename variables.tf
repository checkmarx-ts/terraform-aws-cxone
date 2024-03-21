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

variable "secondary_vpc_cidr" {
  description = "A secondary CIDR block for pods networking."
  type        = string
  default     = null
  nullable    = true
}

variable "administrator_iam_role_arn" {
  description = "The IAM role for the administrator group that will allow system administration (e.g. EKS master)"
  type        = string
  nullable    = false
}

variable "domain" {
  description = "Domain for the AWS hosted zone (e.g. example.com)"
  type        = string
  nullable    = false
}

variable "subdomain" {
  description = "Subdomain for the hosted zone domain (e.g. checkmarx.) The subdomain will be prepended to the domain for DNS records.)"
  type        = string
  nullable    = false
}

variable "cxone_admin_password" {
  description = "The password used to login to CxOne"
  type        = string
  nullable    = false
}

variable "cxone_admin_email" {
  description = "Sets the default admin email address for CxOne"
  type        = string
  nullable    = false
}

variable "SMTP_endpoint" {
  description = "Defines the endpoint of smtp server"
  type        = string
  nullable    = false
}

variable "SMTP_port" {
  description = "Defines the smtp port number"
  type        = number
  nullable    = false
}

variable "SMTP_from_sender" {
  description = "Defines the smtp from sender address"
  type        = string
  nullable    = false
}

variable "object_storage_url" {
  description = "The s3 object storage url to use (region dependent) e.g. s3.us-west-2.amazonaws.com"
  type        = string
  nullable    = false
}

variable "object_storage_access_key" {
  description = "The s3 object storage IAM user's access key."
  type        = string
  nullable    = false
}

variable "object_storage_secret_key" {
  description = "The s3 object storage IAM user's secret key."
  type        = string
  nullable    = false
}
