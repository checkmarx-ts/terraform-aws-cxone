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
  default = "r7g.large.search"
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

variable "enable_dedicated_master_nodes" {
  type    = bool
  default = false
}

variable "dedicated_master_count" {
  type    = number
  default = 3
}

variable "dedicated_master_type" {
  type    = string
  default = "m6g.large.search"
}

variable "ebs_throughput" {
  type    = number
  default = 125  
}

variable "ebs_iops" {
  type    = number
  default = 3000  
}

variable "username" {
  type = string
  description = "The username for the OpenSearch master user."
  default = "ast"  
}

variable "engine_version" {
  type    = string
  default = "OpenSearch_2.19"
}