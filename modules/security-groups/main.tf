resource "aws_security_group" "internal" {
  name        = "internal-${var.deployment_id}-sg"
  description = "Internal security group for AST deployment called ${var.deployment_id}."
  vpc_id      = var.vpc_id
}

resource "aws_security_group" "external" {
  name        = "external-${var.deployment_id}-sg"
  description = "External Security group for AST deployment called ${var.deployment_id}."
  vpc_id      = var.vpc_id
}


resource "aws_security_group" "rds" {
  name        = "rds-${var.deployment_id}-sg"
  description = "RDS security group for AST deployment called ${var.deployment_id}."
  vpc_id      = var.vpc_id
}

resource "aws_security_group" "elasticache" {
  name        = "elasticache-${var.deployment_id}-sg"
  description = "Elasticache security group for AST deployment called ${var.deployment_id}."
  vpc_id      = var.vpc_id
}
