variable "region" {
  type        = string
  description = "The AWS region e.g. us-east-1, us-west-2, etc."
}

variable "admin_email" {
  type        = string
  description = "The email of the first admin user."
}

variable "admin_password" {
  type        = string
  description = "The password for the first admin user. Must be > 14 characters."
}

variable "fqdn" {
  type        = string
  description = "The fully qualified domain name that will be used for the Checkmarx One deployment"
}

variable "acm_certificate_arn" {
  type        = string
  description = "The ARN for the ACM certificate to use to configure SSL with."
}

variable "deployment_id" {
  description = "The id of the deployment. Will be used to name resources like EKS cluster, etc."
  type        = string
  nullable    = false
  validation {
    condition     = (length(var.deployment_id) >= 3)
    error_message = "The deployment_id must be greater than 3 characters."
  }
}

variable "vpc_id" {
  description = "The VPC Id Checkmarx One is deployed into."
  type        = string
}

variable "bucket_suffix" {
  description = "The id of the deployment. Will be used to name resources like EKS cluster, etc."
  type        = string
  nullable    = false
  validation {
    condition     = (length(var.bucket_suffix) > 3)
    error_message = "The deployment_id must be greater than 3 characters."
  }
}

variable "cxone_version" {
  type        = string
  description = "The version of CxOne to install"
}

variable "release_channel" {
  type        = string
  description = "The release channel to deploy from"
}

variable "license_file" {
  type        = string
  description = "The path to the license file to use"
}

variable "kots_admin_password" {
  type        = string
  description = "The Kots password to use"
}

variable "ms_replica_count" {
  type        = number
  description = "The microservices replica count (e.g. a minimum)"
  default     = 3
}

variable "cluster_autoscaler_iam_role_arn" {
  type     = string
  nullable = true
}

variable "external_dns_iam_role_arn" {
  type     = string
  nullable = true
}

variable "load_balancer_controller_iam_role_arn" {
  type     = string
  nullable = true
}

variable "karpenter_iam_role_arn" {
  type     = string
  nullable = true
}

variable "cluster_endpoint" {
  type     = string
  nullable = true
}

variable "nodegroup_iam_role_name" {
  type     = string
  nullable = true
}

variable "availability_zones" {
  type     = list(string)
  nullable = false
}

variable "pod_eniconfig" {
  description = "The ENIConfigs for EKS custom networking configuration."
  type        = string
  nullable    = true
}

#******************************************************************************
#   S3 Access Configuration
#******************************************************************************
variable "object_storage_endpoint" {
  type        = string
  description = "The S3 endpoint to use to access buckets"
}

variable "object_storage_access_key" {
  type        = string
  description = "The S3 access key to use to access buckets"
}
variable "object_storage_secret_key" {
  type        = string
  description = "The S3 secret key to use to access buckets"
}

variable "postgres_host" {
  type        = string
  description = "The endpoint for the main RDS server."
}

variable "postgres_user" {
  type        = string
  description = "The user name for the main RDS server."
  default     = "ast"
}

variable "postgres_password" {
  type        = string
  description = "The user name for the main RDS server."
  default     = "ast"
}

variable "postgres_database_name" {
  type        = string
  description = "The name of the main database."
  default     = "ast"
}

variable "redis_address" {
  type        = string
  description = "The redis endpoint."
}


#******************************************************************************
#   Elasticsearch Configuration
#******************************************************************************

variable "elasticsearch_host" {
  type    = string
  default = "The elasticsearc host address."
}

variable "elasticsearch_password" {
  type    = string
  default = "The elasticsearch password."
}

#******************************************************************************
#   SMTP Configuration
#******************************************************************************
variable "smtp_host" {
  description = "The hostname of the SMTP server."
  type        = string
}

variable "smtp_port" {
  description = "The port of the SMTP server."
  type        = number
}

variable "smtp_user" {
  description = "The smtp user name."
  type        = string
}

variable "smtp_password" {
  description = "The smtp password."
  type        = string
}

variable "smtp_from_sender" {
  description = "The address to use in the from field when sending emails."
  type        = string
}