variable "deployment_id" {
  description = "The id of the deployment. Will be used to name resources."
  type        = string
  nullable    = false
  validation {
    condition     = (length(var.deployment_id) > 0)
    error_message = "The deployment_id is required."
  }
}

variable "vpc_id" {
  description = "The VPC ID to import."
  type        = string
  nullable    = false
}

variable "secondary_vpc_cidr" {
  description = "The secondary VPC CIDR to attach to the VPC."
  type        = string
  nullable    = false
  validation {
    condition     = cidrnetmask(var.secondary_vpc_cidr) == "255.255.0.0" || cidrnetmask(var.secondary_vpc_cidr) == "255.255.128.0" || cidrnetmask(var.secondary_vpc_cidr) == "255.255.192.0"
    error_message = "secondary_vpc_cidr must be a /16, /17, or /18 network."
  }
}

variable "existing_private_subnets" {
  description = "The private subnets to import and tag."
  type        = list(string)
  nullable    = false
  validation {
    condition     = (length(var.existing_private_subnets) == 3)
    error_message = "3 subnet ids are expected."
  }
}
