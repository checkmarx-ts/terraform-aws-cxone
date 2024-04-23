#******************************************************************************
#   Base Infrastructure Configuration - These variables are used by the example itself
#******************************************************************************

variable "route_53_hosted_zone_id" {
  type        = string
  description = "The hosted zone id for route 53 in which to create dns and certificates."
  nullable    = true
}

variable "fqdn" {
  type        = string
  description = "The fully qualified domain name that will be used for the Checkmarx One deployment"
}

variable "acm_certificate_arn" {
  type        = string
  description = "The ARN to the SSL certificate in AWS ACM to use for securing the load balancer"
  default     = null
}

variable "ms_replica_count" {
  type        = number
  description = "The microservices replica count (e.g. a minimum)"
  default     = 3
}

#******************************************************************************
#   S3 Configuration
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
  default     = 587
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

#******************************************************************************
#   Kots & Installation Configuration
#******************************************************************************
variable "kots_cxone_version" {
  description = "The version of Checkmarx One to install"
  type        = string
}

variable "kots_release_channel" {
  description = "The release channel from which to install Checkmarx One"
  type        = string
  default     = "beta"
}

variable "kots_license_file" {
  description = "The path to the kots license file to install Checkamrx One with."
  type        = string
}

variable "kots_admin_email" {
  description = "The email address of the Checkmarx One first admin user."
  type        = string
}