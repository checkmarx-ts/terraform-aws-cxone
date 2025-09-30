# ---------------------------------------------------------------------------------------------------------------------
# IAM Role for
# ---------------------------------------------------------------------------------------------------------------------


# ---------------------------------------------------------------------------------------------------------------------
# Related Variables & Outputs
# ---------------------------------------------------------------------------------------------------------------------
variable "vpc_cni_role_arn" {
  type        = string
  description = "The pre-existing IAM role arn for the VPC CNI Driver for use with EKS Pod Identity Agent."
  default     = null
}

variable "vpc_cni_role_permissions_boundary_policy_arn" {
  description = "The permissions boundary policy arn for the VPC CNI IAM role."
  type        = string
  default     = null
}

output "vpc_cni_role_arn" {
  value = var.vpc_cni_role_arn == null ? module.vpc_cni_pod_identity[0].iam_role_arn : var.vpc_cni_role_arn
}


# ---------------------------------------------------------------------------------------------------------------------
# Related Resources
# ---------------------------------------------------------------------------------------------------------------------

module "vpc_cni_pod_identity" {
  count   = var.vpc_cni_role_arn == null ? 1 : 0
  source  = "terraform-aws-modules/eks-pod-identity/aws"
  version = "1.10.0"

  name                      = "${var.deployment_id}-vpc-cni"
  use_name_prefix           = false
  description               = "VPC CNI IAM Role for EKS Pod Identity Agent for the CxOne deployment ${var.deployment_id}"
  attach_aws_vpc_cni_policy = true
  aws_vpc_cni_enable_ipv4   = true
  permissions_boundary_arn  = var.vpc_cni_role_permissions_boundary_policy_arn
  policy_name_prefix        = var.deployment_id
}

# Pod Identity Association is always created, even if the role was pre-existing.
resource "aws_eks_pod_identity_association" "vpc_cni" {
  cluster_name    = var.eks_cluster_name
  namespace       = "kube-system"
  service_account = "aws-node" #kube-proxy
  role_arn        = var.vpc_cni_role_arn == null ? module.vpc_cni_pod_identity[0].iam_role_arn : var.vpc_cni_role_arn
}

