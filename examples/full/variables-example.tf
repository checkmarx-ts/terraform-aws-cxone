#******************************************************************************
#   Base Infrastructure Configuration - These variables are used by the example itself
#******************************************************************************

variable "vpc_cidr" {
  type        = string
  description = "The primary VPC CIDR block to create the VPC with."
}

variable "secondary_vpc_cidr" {
  type        = string
  description = "The secondary VPC CIDR block to associate with the VPC."
  default     = null
}

variable "interface_vpc_endpoints" {
  type        = list(string)
  description = "A list of services that vpc endpoints are created for."
  default     = ["ec2", "ec2messages", "ssm", "ssmmessages", "ecr.api", "ecr.dkr", "kms", "logs", "sts", "elasticloadbalancing", "autoscaling"]
}

variable "create_s3_endpoint" {
  type        = bool
  description = "Enables creation of the s3 gateway VPC interface endpoint."
  default     = true
}

variable "route_53_hosted_zone_id" {
  type        = string
  description = "The hosted zone id for route 53 in which to create dns and certificates."
  nullable    = true
}

variable "fqdn" {
  type        = string
  description = "The fully qualified domain name that will be used for the Checkmarx One deployment"
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
# variable "smtp_host" {
#   description = "The hostname of the SMTP server."
#   type        = string
# }

variable "smtp_port" {
  description = "The port of the SMTP server."
  type        = number
  default     = 587
}

# variable "smtp_user" {
#   description = "The smtp user name."
#   type        = string
# }

# variable "smtp_password" {
#   description = "The smtp password."
#   type        = string
# }

# variable "smtp_from_sender" {
#   description = "The address to use in the from field when sending emails."
#   type        = string
# }

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