resource "aws_security_group" "rds" {
  name        = "rds-${var.deployment_id}-sg"
  description = "RDS security group for Checkmarx One deployment called ${var.deployment_id}."
  vpc_id      = var.vpc_id
}

resource "aws_security_group_rule" "ingress_rds_internal" {
  description       = "RDS vpc ingress"
  type              = "ingress"
  from_port         = 5432
  to_port           = 5432
  protocol          = "tcp"
  cidr_blocks       = [var.vpc_cidr]
  security_group_id = aws_security_group.rds.id
}