# ---------------------------------------------------------------------------------------------------------------------
# IAM Role for the EBS CSI Driver
# ---------------------------------------------------------------------------------------------------------------------


# ---------------------------------------------------------------------------------------------------------------------
# Related Variables & Outputs
# ---------------------------------------------------------------------------------------------------------------------

variable "ebs_csi_role_arn" {
  type        = string
  description = "The pre-existing IAM role arn for the EBS CSI Driver for use with EKS Pod Identity Agent."
  default     = null
}

variable "ebs_csi_role_permissions_boundary_policy_arn" {
  description = "The permissions boundary policy arn for the EBS CSI Driver IAM role."
  type        = string
  default     = null
}

output "ebs_csi_role_arn" {
  value = var.ebs_csi_role_arn == null ? module.ebs_csi_pod_identity[0].iam_role_arn : var.ebs_csi_role_arn
}

# ---------------------------------------------------------------------------------------------------------------------
# Related Resources
# ---------------------------------------------------------------------------------------------------------------------

module "ebs_csi_pod_identity" {
  count   = var.ebs_csi_role_arn == null ? 1 : 0
  source  = "terraform-aws-modules/eks-pod-identity/aws"
  version = "1.10.0"

  name                      = "${var.deployment_id}-ebs-csi"
  use_name_prefix           = false
  description               = "EBS CSI IAM Role for EKS Pod Identity Agent for the CxOne deployment ${var.deployment_id}"
  attach_aws_ebs_csi_policy = true
  aws_ebs_csi_kms_arns      = [var.eks_kms_key_arn]
  permissions_boundary_arn  = var.ebs_csi_role_permissions_boundary_policy_arn
}

# Pod Identity Association is always created, even if the role was pre-existing.
resource "aws_eks_pod_identity_association" "ebs_csi" {
  cluster_name    = var.eks_cluster_name
  namespace       = "kube-system"
  service_account = "ebs-csi-controller-sa"
  role_arn        = var.ebs_csi_role_arn == null ? module.ebs_csi_pod_identity[0].iam_role_arn : var.ebs_csi_role_arn
}
