variable "deployment_id" {
  description = "The id of the deployment. Will be used to name resources like EKS cluster, etc."
  type        = string
  nullable    = false
  validation {
    condition     = (length(var.deployment_id) > 0)
    error_message = "The deployment_id is required."
  }
}

variable "subnet_id" {
    description = "The subnet to deploy the bastion host into."
    type = string
}

variable "instance_type" {
    description = "The instance type of the bastion host."
    type = string
    default = "t3.medium"
}

variable "key_name" {
    description = "The ec2 key pair name for the bastion host."
    type = string
}

variable "remote_management_cidrs" {
    description = "The cidrs to allow remote management ingress from"
    type = list(string)
}