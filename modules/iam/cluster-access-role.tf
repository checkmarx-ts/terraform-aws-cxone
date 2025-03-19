# ---------------------------------------------------------------------------------------------------------------------
# IAM Role for the EKS Cluster Access (e.g. who can manage cluster via kubectl and similar)
# ---------------------------------------------------------------------------------------------------------------------


# ---------------------------------------------------------------------------------------------------------------------
# Related Variables & Outputs
# ---------------------------------------------------------------------------------------------------------------------


variable "cluster_access_role_arn" {
  type        = string
  description = "The pre-existing IAM role arn for the EKS Cluster Access. A cluster role will be created if not provided."
  default     = null
}

variable "cluster_access_role_permissions_boundary_policy_arn" {
  description = "The permissions boundary policy arn for the cluster access role IAM role."
  type        = string
  default     = null
}

output "cluster_access_iam_role_arn" {
  value = var.cluster_access_role_arn == null ? aws_iam_role.cluster_access[0].arn : var.cluster_access_role_arn
}

# ---------------------------------------------------------------------------------------------------------------------
# Resources
# ---------------------------------------------------------------------------------------------------------------------

data "aws_iam_policy_document" "cluster_access" {
  count = var.cluster_access_role_arn == null ? 1 : 0
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = [var.administrator_iam_role_arn]
    }
  }
}

resource "aws_iam_role" "cluster_access" {
  count                = var.cluster_access_role_arn == null ? 1 : 0
  name                 = "${var.deployment_id}-cluster-access"
  assume_role_policy   = data.aws_iam_policy_document.cluster_access[0].json
  description          = "Role used for admin EKS cluster access for the deployment with id ${var.deployment_id}."
  permissions_boundary = var.cluster_access_role_permissions_boundary_policy_arn
}

