variable "domain" {
  description = "Domain for the AWS hosted zone (e.g. example.com)"
  type        = string
  nullable    = false
}

variable "subdomain" {
  description = "Subdomain for the hosted zone domain (e.g. checkmarx.) The subdomain will be prepended to the domain for DNS records.)"
  type        = string
  nullable    = false
}

variable "deployment_id" {
  description = "The id of the deployment. Will be used to name resources like EKS cluster, etc."
  type        = string
  nullable    = false
  validation {
    condition     = (length(var.deployment_id) > 0)
    error_message = "The deployment_id is required."
  }
}