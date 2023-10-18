data "aws_iam_policy_document" "aws_cluster_access" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = ["${var.iam_role.customer_arn}"]
    }
  }
}

resource "aws_iam_role" "customer_iam_role" {
  count = "${var.iam_role.customer_arn}" != "" ? 1 : 0

  name               = "${var.deployment_id}-iam-role"
  assume_role_policy = data.aws_iam_policy_document.aws_cluster_access.json
}