variable "deployment_id" {
  description = "The id of the deployment. Will be used to name resources like EKS cluster, etc."
  type        = string
  nullable    = false
  validation {
    condition     = (length(var.deployment_id) > 0)
    error_message = "The deployment_id is required."
  }
}


variable "s3_retention_period" {
  description = "S3 Retention Period"
  type        = string
  default     = "90"
}

variable "s3_bucket_versioning_status" {
  type        = string
  description = "S3 Bucket versioning Status"
  default     = "Disabled"
}

variable "s3_cors_allowed_origins" {
  type        = list(string)
  description = "The list of allowed origins for Cross Origin Request Sharing (CORS)"
}
