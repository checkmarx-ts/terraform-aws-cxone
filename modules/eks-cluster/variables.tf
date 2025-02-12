
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
  default     = "1.30"
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

variable "launch_template_tags" {
  type        = map(string)
  description = "Tags to associate with launch templates for node groups"
  default     = null
}

variable "additional_node_security_group_ids" {
  type        = list(string)
  description = "Additional security group ids to add to node group instances."
  default     = []
}

variable "ec2_key_name" {
  type        = string
  description = "The keyname that should be used for the instances."
  default     = null
}

variable "pod_custom_networking_subnets" {
  type = list(object({
    availability_zone = string
    subnet_id         = string
  }))
  description = "A list of subnet ids and availability zones for deploying pods into with custom networking."
  default     = null
}

variable "cluster_autoscaler_image_repository" {
  type        = string
  description = "The repository to pull images from for cluster autoscaler"
  default     = "k8s.gcr.io/autoscaling/cluster-autoscaler"
}

variable "self_managed_node_groups" {
  type = list(object({
    name                   = string
    min_size               = string
    desired_size           = string
    max_size               = string
    launch_template_id     = string
    autoscaling_group_tags = optional(map(string), {})
    labels                 = optional(map(string), {})
    taints                 = optional(map(object({ key = string, value = string, effect = string })), {})
  }))
}

variable "eks_create_ebs_csi_irsa" {
  type        = bool
  description = "Create EBS CSI irsa iam role"
  default     = false
}

variable "eks_create_cluster_autoscaler_irsa" {
  type        = bool
  description = "Create cluster autoscaler irsa iam role"
  default     = false
}

variable "eks_create_external_dns_irsa" {
  type        = bool
  description = "Create external dns irsa iam role"
  default     = false
}

variable "eks_create_load_balancer_controller_irsa" {
  type        = bool
  description = "Create load balancer controller irsa iam role"
  default     = false
}


variable "coredns_version" {
  type        = string
  description = "The version of the EKS Core DNS Addon."
  default     = "v1.11.4-eksbuild.2"
}

variable "kube_proxy_version" {
  type        = string
  description = "The version of the EKS Kube Proxy Addon."
  default     = "v1.30.7-eksbuild.2"
}

variable "vpc_cni_version" {
  type        = string
  description = "The version of the EKS VPC CNI Addon."
  default     = "v1.19.2-eksbuild.1"
}

variable "aws_ebs_csi_driver_version" {
  type        = string
  description = "The version of the EKS EBS CSI Addon."
  default     = "v1.39.0-eksbuild.1"
}

variable "eks_pre_bootstrap_user_data" {
  type        = string
  description = "User data to insert before bootstrapping script."
  default     = ""
}