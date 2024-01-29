resource "aws_security_group" "opensearch" {
  name        = "opensearch-${var.deployment_id}-sg"
  description = "Opensearch security group for Checkmarx One deployment called ${var.deployment_id}."
  vpc_id      = var.vpc_id
}


resource "aws_security_group_rule" "ingress_opensearch_internal" {
  description       = "Elasticache tcp/443 from vpc"
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = [var.vpc_cidr]
  security_group_id = aws_security_group.opensearch.id
}
