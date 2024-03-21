resource "aws_security_group" "vpc_endpoints" {
  name        = "vpc-endpoints-${var.deployment_id}-sg"
  description = "VPC Endpoints security group for Checkmarx One deployment called ${var.deployment_id}."
  vpc_id      = var.vpc_id
}

resource "aws_security_group_rule" "vpc_endpoint_ingress" {
  description       = "https from vpc"
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = local.internal_vpc_cidrs
  security_group_id = aws_security_group.vpc_endpoints.id
}
