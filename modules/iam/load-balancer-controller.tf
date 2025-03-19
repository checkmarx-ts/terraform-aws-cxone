# ---------------------------------------------------------------------------------------------------------------------
# IAM Role for
# ---------------------------------------------------------------------------------------------------------------------


# ---------------------------------------------------------------------------------------------------------------------
# Related Variables & Outputs
# ---------------------------------------------------------------------------------------------------------------------
variable "load_balancer_controller_role_arn" {
  type        = string
  description = "The pre-existing IAM role arn for the load balancer controller for use with EKS Pod Identity Agent."
  default     = null
}

variable "load_balancer_controller_role_permissions_boundary_policy_arn" {
  description = "The permissions boundary policy arn for the Load Balancer Controller IAM role."
  type        = string
  default     = null
}

output "load_balancer_controller_role_arn" {
  value = var.load_balancer_controller_role_arn == null ? module.load_balancer_controller_pod_identity[0].iam_role_arn : var.load_balancer_controller_role_arn
}

# ---------------------------------------------------------------------------------------------------------------------
# Related Resources
# ---------------------------------------------------------------------------------------------------------------------

module "load_balancer_controller_pod_identity" {
  count   = var.load_balancer_controller_role_arn == null ? 1 : 0
  source  = "terraform-aws-modules/eks-pod-identity/aws"
  version = "1.10.0"

  name                            = "${var.deployment_id}-load-balancer-controller"
  use_name_prefix                 = false
  description                     = "Load balancer controller IAM Role for EKS Pod Identity Agent for the CxOne deployment ${var.deployment_id}"
  attach_aws_lb_controller_policy = true
  permissions_boundary_arn        = var.load_balancer_controller_role_permissions_boundary_policy_arn
}

# Pod Identity Association is always created, even if the role was pre-existing.
resource "aws_eks_pod_identity_association" "load_balancer_controller" {
  cluster_name    = var.eks_cluster_name
  namespace       = "kube-system"
  service_account = "aws-load-balancer-controller"
  role_arn        = var.load_balancer_controller_role_arn == null ? module.load_balancer_controller_pod_identity[0].iam_role_arn : var.load_balancer_controller_role_arn
}
