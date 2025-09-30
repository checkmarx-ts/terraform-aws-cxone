# ---------------------------------------------------------------------------------------------------------------------
# IAM Role for Cluster Autoscaler
# ---------------------------------------------------------------------------------------------------------------------


# ---------------------------------------------------------------------------------------------------------------------
# Related Variables & Outputs
# ---------------------------------------------------------------------------------------------------------------------
variable "cluster_autoscaler_role_arn" {
  type        = string
  description = "The pre-existing IAM role arn for the cluster autoscaler for use with EKS Pod Identity Agent."
  default     = null
}

variable "cluster_autoscaler_role_permissions_boundary_policy_arn" {
  description = "The permissions boundary policy arn for the cluster autoscaler IAM role."
  type        = string
  default     = null
}

output "cluster_autoscaler_role_arn" {
  value = var.cluster_autoscaler_role_arn == null ? module.cluster_autoscaler_pod_identity[0].iam_role_arn : var.cluster_autoscaler_role_arn
}

# ---------------------------------------------------------------------------------------------------------------------
# Related Resources
# ---------------------------------------------------------------------------------------------------------------------

module "cluster_autoscaler_pod_identity" {
  count   = var.cluster_autoscaler_role_arn == null ? 1 : 0
  source  = "terraform-aws-modules/eks-pod-identity/aws"
  version = "1.10.0"

  name                             = "${var.deployment_id}-cluster-autoscaler"
  use_name_prefix                  = false
  description                      = "Cluster autoscaler IAM Role for EKS Pod Identity Agent for the CxOne deployment ${var.deployment_id}"
  attach_cluster_autoscaler_policy = true
  cluster_autoscaler_cluster_names = [var.eks_cluster_name]
  permissions_boundary_arn         = var.cluster_autoscaler_role_permissions_boundary_policy_arn
  policy_name_prefix               = var.deployment_id
}

# Pod Identity Association is always created, even if the role was pre-existing.
resource "aws_eks_pod_identity_association" "cluster_autoscaler" {
  cluster_name    = var.eks_cluster_name
  namespace       = "kube-system"
  service_account = "cluster-autoscaler"
  role_arn        = var.cluster_autoscaler_role_arn == null ? module.cluster_autoscaler_pod_identity[0].iam_role_arn : var.cluster_autoscaler_role_arn
}

