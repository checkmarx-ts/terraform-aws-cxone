
data "aws_iam_policy_document" "aws_cluster_access" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = [var.administrator_iam_role_arn]
    }
  }
}

resource "aws_iam_role" "cluster_access_role" {

  name               = "${var.deployment_id}-iam-role"
  assume_role_policy = data.aws_iam_policy_document.aws_cluster_access.json
}

