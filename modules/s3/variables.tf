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

variable "s3_allowed_origins" {
  type        = list(string)
  description = "The list of allowed origins for Cross Origin Request Sharing (CORS)"
}

variable "control_object_ownership" {
  default     = true
  type        = bool
  description = "Controls s3 module control_object_ownership"
}

variable "block_public_acls" {
  default     = true
  type        = bool
  description = "Controls s3 module block_public_acls"
}

variable "block_public_policy" {
  default     = true
  type        = bool
  description = "Controls s3 module block_public_policy"
}

variable "ignore_public_acls" {
  default     = true
  type        = bool
  description = "Controls s3 module ignore_public_acls"
}

variable "restrict_public_buckets" {
  default     = true
  type        = bool
  description = "Controls s3 module restrict_public_buckets"
}

variable "attach_deny_insecure_transport_policy" {
  default     = true
  type        = bool
  description = "Controls s3 module attach_deny_insecure_transport_policy"
}
