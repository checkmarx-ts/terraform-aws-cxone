

variable "deployment_id" {
  description = "The id of the deployment. Will be used to name resources like EKS cluster, etc."
  type        = string
  nullable    = false
  validation {
    condition     = (length(var.deployment_id) > 0)
    error_message = "The deployment_id is required."
  }
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC. Must be a /16 network"
  type        = string
  validation {
    condition     = (cidrnetmask(var.vpc_cidr) == "255.255.0.0")
    error_message = "vpc_cidr must be a /16 network with netmask 255.255.0.0 e.g. 10.1.0.0/16"
  }
}

variable "nat_per_az" {
  description = "Determines if a NAT Gateway will be created per each availabilty zone."
  type        = bool
  default     = false
}

variable "single_nat" {
  description = "Determines if a single NAT Gateway will be created for all availabilty zones."
  type        = bool
  default     = true
}

