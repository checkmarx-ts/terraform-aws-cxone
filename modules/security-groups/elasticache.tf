resource "aws_security_group" "elasticache" {
  name        = "elasticache-${var.deployment_id}-sg"
  description = "Elasticache security group for Checkmarx One deployment called ${var.deployment_id}."
  vpc_id      = var.vpc_id
}


resource "aws_security_group_rule" "ingress_elasticache_internal" {
  description       = "RDS vpc ingress"
  type              = "ingress"
  from_port         = 6379
  to_port           = 6379
  protocol          = "tcp"
  cidr_blocks       = local.internal_vpc_cidrs
  security_group_id = aws_security_group.elasticache.id
}