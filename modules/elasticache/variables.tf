variable "deployment_id" {
  description = "The id of the deployment. Will be used to name resources like EKS cluster, etc."
  type        = string
  nullable    = false
  validation {
    condition     = (length(var.deployment_id) > 0)
    error_message = "The deployment_id is required."
  }
}

variable "kms_key_arn" {
  description = "The ARN of the KMS key to use for encryption."
  type        = string
  nullable    = false
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

variable "redis_auth_token" {
  type        = string
  sensitive   = true
  description = "Auth token for Elasticache Redis DB"
  default     = ""
}

variable "redis_nodes" {
  type = object({
    instance_type      = string
    replicas_per_shard = number
    number_of_shards   = number
  })
  validation {
    condition     = (var.redis_nodes.instance_type != "" && var.redis_nodes.number_of_shards > 0)
    error_message = "The field instance_type cannot be empty and the number of db shards must be greater than zero."
  }
  default = {
    instance_type      = "cache.m6g.large",
    number_of_shards   = 1,
    replicas_per_shard = 1
  }
  description = "Configuration for the Elasticache Redis DB nodes"
}