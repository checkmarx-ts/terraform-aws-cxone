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