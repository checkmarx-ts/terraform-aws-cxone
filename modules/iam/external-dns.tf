# ---------------------------------------------------------------------------------------------------------------------
# IAM Role for use with External DNS
# ---------------------------------------------------------------------------------------------------------------------


# ---------------------------------------------------------------------------------------------------------------------
# Related Variables & Outputs
# ---------------------------------------------------------------------------------------------------------------------

variable "external_dns_role_arn" {
  type        = string
  description = "The pre-existing IAM role arn for the external dns for use with EKS Pod Identity Agent. A default role is created when not provided."
  default     = null
}

variable "create_external_dns_pod_identity" {
  type        = bool
  description = "Controls creation of pod identity association for external dns iam role."
  default     = false
}

variable "external_dns_hosted_zone_arns" {
  type        = list(string)
  description = "The route53 hosted zone arns for use with external dns."
  default     = []
}

output "external_dns_role_arn" {
  value = var.external_dns_role_arn == null ? module.external_dns_pod_identity[0].iam_role_arn : var.external_dns_role_arn
}

# ---------------------------------------------------------------------------------------------------------------------
# Related Resources
# ---------------------------------------------------------------------------------------------------------------------

module "external_dns_pod_identity" {
  count   = var.external_dns_role_arn == null ? 1 : 0
  source  = "terraform-aws-modules/eks-pod-identity/aws"
  version = "1.10.0"

  name            = "${var.deployment_id}-external-dns"
  use_name_prefix = false
  description     = "External DNS IAM Role for EKS Pod Identity Agent for the CxOne deployment ${var.deployment_id}"

  attach_external_dns_policy    = true
  external_dns_hosted_zone_arns = var.external_dns_hosted_zone_arns
}

# Pod Identity Association is always created, even if the role was pre-existing.
resource "aws_eks_pod_identity_association" "external_dns" {
  count           = var.create_external_dns_pod_identity ? 1 : 0
  cluster_name    = var.eks_cluster_name
  namespace       = "kube-system"
  service_account = "external-dns"
  role_arn        = var.external_dns_role_arn == null ? module.external_dns_pod_identity[0].iam_role_arn : var.external_dns_role_arn
}
