variable "deployment_id" {
  description = "The id of the deployment. Will be used to name resources like EKS cluster, etc."
  type        = string
  nullable    = false
  validation {
    condition     = (length(var.deployment_id) > 0)
    error_message = "The deployment_id is required."
  }
}

variable "administrator_iam_role_arn" {
  description = "The AWS ARN to the IAM role that will be used by Administrators and granted management access to EKS and other services."
  nullable    = false
}

variable "s3_bucket_name_suffix" {
  description = "The suffix of the S3 buckets that Minio will manage."
  nullable    = false
}

variable "create_node_role" {
  type        = bool
  description = "Create IAM role for EKS Nodes"
  default     = true
}

variable "create_ebs_csi_irsa" {
  type        = bool
  description = "Create EBS CSI irsa iam role"
  default     = true
}

variable "create_cluster_autoscaler_irsa" {
  type        = bool
  description = "Create cluster autoscaler irsa iam role"
  default     = true
}

variable "create_external_dns_irsa" {
  type        = bool
  description = "Create external dns irsa iam role"
  default     = true
}

variable "create_load_balancer_controller_irsa" {
  type        = bool
  description = "Create load balancer controller irsa iam role"
  default     = true
}

variable "create_cluster_access_role" {
  type        = bool
  description = "Create IAM role for cluster access"
  default     = true
}

variable "eks_kms_key_arn" {
  description = "The ARN of the KMS key to use for cluster secrets encryption."
  type        = string
  nullable    = false
}

variable "oidc_provider_arn" {
  description = "The OIDC provider ARN for the EKS cluster."
  type        = string
  nullable    = false
}
