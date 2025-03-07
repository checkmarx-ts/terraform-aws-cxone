# ---------------------------------------------------------------------------------------------------------------------
# IAM Role for the RDS Enhanced Monitoring
# ---------------------------------------------------------------------------------------------------------------------

# ---------------------------------------------------------------------------------------------------------------------
# Related Variables & Outputs
# ---------------------------------------------------------------------------------------------------------------------

variable "rds_role_arn" {
  type        = string
  description = "The pre-existing IAM role arn for RDS Enhanced Monitoring. A role will be created if not provided."
  default     = null
}

output "rds_role_arn" {
  value = var.rds_role_arn == null ? aws_iam_role.rds[0].arn : var.rds_role_arn
}

# ---------------------------------------------------------------------------------------------------------------------
# Related Resources
# ---------------------------------------------------------------------------------------------------------------------

# AmazonRDSEnhancedMonitoringRole
data "aws_iam_policy" "AmazonRDSEnhancedMonitoringRole" {
  count = var.rds_role_arn == null ? 1 : 0
  arn   = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

resource "aws_iam_role_policy_attachment" "AmazonRDSEnhancedMonitoringRole" {
  count      = var.rds_role_arn == null ? 1 : 0
  role       = aws_iam_role.rds[0].name
  policy_arn = data.aws_iam_policy.AmazonRDSEnhancedMonitoringRole[0].arn
}


# IAM Role & Profile
resource "aws_iam_role" "rds" {
  count              = var.rds_role_arn == null ? 1 : 0
  name               = "${var.deployment_id}-rds"
  description        = "IAM Role for Checkmarx One RDS with deployment id ${var.deployment_id}."
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "monitoring.rds.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": "RDSEnhancedMonitoring"
    }
  ]
}
EOF
}

resource "aws_iam_instance_profile" "rds" {
  count = var.rds_role_arn == null ? 1 : 0
  name  = "${var.deployment_id}-rds"
  role  = aws_iam_role.rds[0].name
}
