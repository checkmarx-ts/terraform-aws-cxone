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

variable "subnet_ids" {
  type        = list(string)
  nullable    = false
  description = "The subnet_ids to deploy into."
}

variable "enable_private_endpoint" {
  type    = bool
  default = true
}

variable "enable_public_endpoint" {
  type    = bool
  default = true
}

variable "eks_cluster_version" {
  description = "EKS Kubernetes version to be used"
  type        = string
  default     = "1.27"
  nullable    = false
}

variable "eks_kms_key_arn" {
  description = "The ARN of the KMS key to use for cluster secrets encryption."
  type        = string
  nullable    = false
}

variable "cluster_security_group_id" {
  description = "Existing security group ID to be attached to the cluster."
  type        = string
}

variable "node_security_group_id" {
  description = "ID of an existing security group to attach to the node groups created."
  type        = string
}


variable "default_security_group_ids" {
  description = "A list of security group ids to add to all managed node group nodes by default."
  type        = list(string)
  default     = []
}

variable "cluster_access_iam_role_arn" {
  type        = string
  nullable    = false
  description = "The role for cluster administrators."
}

variable "nodegroup_iam_role_arn" {
  description = "The ARN to the IAM role for the EKS nodes."
  nullable    = false
}

variable "nodegroup_iam_role_name" {
  description = "The ARN to the IAM role for the EKS nodes."
  nullable    = false
}