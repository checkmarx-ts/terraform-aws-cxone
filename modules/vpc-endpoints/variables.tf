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

variable "create_s3_endpoint" {
  type        = bool
  default     = true
  description = "Controls creation of the s3 vpc endpoint."
}

variable "create_autoscaling_endpoint" {
  type        = bool
  default     = true
  description = "Controls creation of the autoscaling vpc endpoint."
}

variable "create_elasticloadbalancing_endpoint" {
  type        = bool
  default     = true
  description = "Controls creation of the elasticloadbalancing vpc endpoint."
}

variable "create_sts_endpoint" {
  type        = bool
  default     = true
  description = "Controls creation of the sts vpc endpoint."
}

variable "create_logs_endpoint" {
  type        = bool
  default     = true
  description = "Controls creation of the logs vpc endpoint."
}

variable "create_kms_endpoint" {
  type        = bool
  default     = true
  description = "Controls creation of the kms vpc endpoint."
}

variable "create_ec2messages_endpoint" {
  type        = bool
  default     = true
  description = "Controls creation of the ec2 messages vpc endpoint."
}

variable "create_ssmmessages_endpoint" {
  type        = bool
  default     = true
  description = "Controls creation of the ssm messages vpc endpoint."
}

variable "create_ssm_endpoint" {
  type        = bool
  default     = true
  description = "Controls creation of the ssm vpc endpoint."
}

variable "create_ecr_dkr_endpoint" {
  type        = bool
  default     = true
  description = "Controls creation of the ECR DKR vpc endpoint."
}

variable "create_ecr_api_endpoint" {
  type        = bool
  default     = true
  description = "Controls creation of the ECR API vpc endpoint."
}

variable "create_ec2_endpoint" {
  type        = bool
  default     = true
  description = "Controls creation of the EC2 vpc endpoint."
}
