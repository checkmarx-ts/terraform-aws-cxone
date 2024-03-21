variable "deployment_id" {
  description = "The id of the deployment. Will be used to name resources like EKS cluster, etc."
  type        = string
  nullable    = false
  validation {
    condition     = (length(var.deployment_id) > 0)
    error_message = "The deployment_id is required."
  }
}

variable "primary_vpc_cidr" {
  description = "Primary CIDR block for the VPC. Must be a /16 network"
  type        = string
}

variable "secondary_vpc_cidr" {
  description = "A secondary CIDR block for pods networking."
  type        = string
  default     = null
  nullable    = true
}

variable "maximum_azs" {
  description = "The maximum number of availability zones to deploy into."
  type        = number
  default     = 3
}
