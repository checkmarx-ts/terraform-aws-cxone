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

variable "subnets" {
  type        = list(string)
  nullable    = false
  description = "The subnets for the VPC Endpoints."
}

variable "security_group_ids" {
  type        = list(string)
  nullable    = false
  description = "The security group ids for the vpc endpoints."
}