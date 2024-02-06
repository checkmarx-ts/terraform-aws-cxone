variable "deployment_id" {
  description = "The id of the deployment. Will be used to name resources like EKS cluster, etc."
  type        = string
  nullable    = false
  validation {
    condition     = (length(var.deployment_id) > 0)
    error_message = "The deployment_id is required."
  }
}


variable "security_group_ids" {
  description = "The id(s) of the security group for the instance."
  type        = list(string)
  nullable    = false
}

variable "subnet_ids" {
  description = "The id(s) of the subnets for the instance."
  type        = list(string)
  nullable    = false
}

variable "tls_security_policy" {
  default = "Policy-Min-TLS-1-2-2019-07"
  type    = string
}

variable "instance_type" {
  default = "r6g.large.elasticsearch"
  type    = string
}

variable "instance_count" {
  default = 2
  type    = number
}

variable "volume_size" {
  default = 100
  type    = number
}


variable "password" {
  type = string
  validation {
    condition     = var.password != ""
    error_message = "The password is not valid."
  }
  sensitive   = true
  description = "Password of the elasticsearch"
}