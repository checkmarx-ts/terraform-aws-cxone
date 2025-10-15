variable "policy" {
  description = "The policy to attach to the KMS key"
  type        = string
  default     = null
}

variable "deletion_window_in_days" {
  description = "The deletion window in days for the KMS key"
  type        = number
  default     = 7
}


variable "enable_key_rotation" {
  description = "Wether to enable key rotation for the KMS key"
  type        = bool
  default     = true
}
