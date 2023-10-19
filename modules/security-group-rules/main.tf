#------------------------------------------------------------------------------
# Internal SG Rules
#------------------------------------------------------------------------------
resource "aws_security_group_rule" "ingress_all_internal" {
  description       = "All protocols"
  type              = "ingress"
  from_port         = -1
  to_port           = -1
  protocol          = "all"
  cidr_blocks       = [var.vpc_cidr]
  security_group_id = var.internal
}

resource "aws_security_group_rule" "egress_all_internal" {
  description       = "All protocols"
  type              = "egress"
  from_port         = -1
  to_port           = -1
  protocol          = "all"
  cidr_blocks       = [var.vpc_cidr]
  security_group_id = var.internal
}


#------------------------------------------------------------------------------
# External SG Rules
#------------------------------------------------------------------------------

resource "aws_security_group_rule" "ingress_http_external" {
  description       = "HTTP"
  type              = "ingress"
  from_port         = 80
  to_port           = 80
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = var.external
}

resource "aws_security_group_rule" "ingress_https_external" {
  description       = "HTTPS"
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = var.external
}

resource "aws_security_group_rule" "ingress_k8s_api_external" {
  description       = "Kubernetes API Server"
  type              = "ingress"
  from_port         = 6443
  to_port           = 6443
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = var.external
}

resource "aws_security_group_rule" "ingress_ssh_external" {
  description       = "SSH"
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = var.external
}

resource "aws_security_group_rule" "ingress_all_icmp_external" {
  description       = "All IPVC ICMP"
  type              = "ingress"
  from_port         = -1
  to_port           = -1
  protocol          = "icmp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = var.external
}


resource "aws_security_group_rule" "egress_all_external" {
  description       = "All protocols"
  type              = "egress"
  from_port         = -1
  to_port           = -1
  protocol          = "all"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = var.external
}


#------------------------------------------------------------------------------
# RDS SG Rules
#------------------------------------------------------------------------------

resource "aws_security_group_rule" "ingress_rds_internal" {
  description       = "RDS vpc ingress"
  type              = "ingress"
  from_port         = 5432
  to_port           = 5432
  protocol          = "tcp"
  cidr_blocks       = [var.vpc_cidr]
  security_group_id = var.rds
}

#------------------------------------------------------------------------------
# RDS SG Rules
#------------------------------------------------------------------------------

resource "aws_security_group_rule" "ingress_elasticache_internal" {
  description       = "RDS vpc ingress"
  type              = "ingress"
  from_port         = 6379
  to_port           = 6379
  protocol          = "tcp"
  cidr_blocks       = [var.vpc_cidr]
  security_group_id = var.elasticache
}