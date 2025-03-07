# ---------------------------------------------------------------------------------------------------------------------
# General purpose variables (not controlling resource creation) are defined here.
# ---------------------------------------------------------------------------------------------------------------------

variable "deployment_id" {
  description = "The id of the deployment. Will be used to name resources like EKS cluster, etc."
  type        = string
  nullable    = false
  validation {
    condition     = (length(var.deployment_id) > 0)
    error_message = "The deployment_id is required."
  }
}

variable "eks_cluster_name" {
  description = "The name of the EKS cluster the IAM roles will be used with."
  type        = string
  nullable    = false
  validation {
    condition     = (length(var.eks_cluster_name) > 0)
    error_message = "The eks_cluster_name is required."
  }
}

variable "administrator_iam_role_arn" {
  description = "The AWS ARN to the IAM role that will be used by Administrators and granted management access to EKS and other services."
  nullable    = false
}

variable "eks_kms_key_arn" {
  description = "The ARN of the KMS key to use for cluster secrets encryption."
  type        = string
  nullable    = false
}
