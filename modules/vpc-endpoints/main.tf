
data "aws_region" "current" {}
resource "aws_vpc_endpoint" "ec2" {
  vpc_id             = var.vpc_id
  service_name       = "com.amazonaws.${data.aws_region.current.name}.ec2"
  vpc_endpoint_type  = "Interface"
  subnet_ids         = var.subnets
  security_group_ids = var.security_group_ids

  private_dns_enabled = true
}

resource "aws_vpc_endpoint" "ecr_api" {
  vpc_id             = var.vpc_id
  service_name       = "com.amazonaws.${data.aws_region.current.name}.ecr.api"
  vpc_endpoint_type  = "Interface"
  subnet_ids         = var.subnets
  security_group_ids = var.security_group_ids

  private_dns_enabled = true
}

# https://docs.aws.amazon.com/eks/latest/userguide/add-ons-images.html
resource "aws_vpc_endpoint" "ecr_dkr" {
  vpc_id             = var.vpc_id
  service_name       = "com.amazonaws.${data.aws_region.current.name}.ecr.dkr"
  vpc_endpoint_type  = "Interface"
  subnet_ids         = var.subnets
  security_group_ids = var.security_group_ids

  private_dns_enabled = true
}

resource "aws_vpc_endpoint" "ssm" {
  vpc_id             = var.vpc_id
  service_name       = "com.amazonaws.${data.aws_region.current.name}.ssm"
  vpc_endpoint_type  = "Interface"
  subnet_ids         = var.subnets
  security_group_ids = var.security_group_ids

  private_dns_enabled = true
}

resource "aws_vpc_endpoint" "ssmmessages" {
  vpc_id             = var.vpc_id
  service_name       = "com.amazonaws.${data.aws_region.current.name}.ssmmessages"
  vpc_endpoint_type  = "Interface"
  subnet_ids         = var.subnets
  security_group_ids = var.security_group_ids

  private_dns_enabled = true
}

resource "aws_vpc_endpoint" "ec2messages" {
  vpc_id             = var.vpc_id
  service_name       = "com.amazonaws.${data.aws_region.current.name}.ec2messages"
  vpc_endpoint_type  = "Interface"
  subnet_ids         = var.subnets
  security_group_ids = var.security_group_ids

  private_dns_enabled = true
}

resource "aws_vpc_endpoint" "kms" {
  vpc_id             = var.vpc_id
  service_name       = "com.amazonaws.${data.aws_region.current.name}.kms"
  vpc_endpoint_type  = "Interface"
  subnet_ids         = var.subnets
  security_group_ids = var.security_group_ids

  private_dns_enabled = true
}

resource "aws_vpc_endpoint" "logs" {
  vpc_id             = var.vpc_id
  service_name       = "com.amazonaws.${data.aws_region.current.name}.logs"
  vpc_endpoint_type  = "Interface"
  subnet_ids         = var.subnets
  security_group_ids = var.security_group_ids

  private_dns_enabled = true
}

resource "aws_vpc_endpoint" "sts" {
  vpc_id             = var.vpc_id
  service_name       = "com.amazonaws.${data.aws_region.current.name}.sts"
  vpc_endpoint_type  = "Interface"
  subnet_ids         = var.subnets
  security_group_ids = var.security_group_ids

  private_dns_enabled = true
}

resource "aws_vpc_endpoint" "elasticloadbalancing" {
  vpc_id             = var.vpc_id
  service_name       = "com.amazonaws.${data.aws_region.current.name}.elasticloadbalancing"
  vpc_endpoint_type  = "Interface"
  subnet_ids         = var.subnets
  security_group_ids = var.security_group_ids

  private_dns_enabled = true
}

# Used by Cluster Autoscaler
resource "aws_vpc_endpoint" "autoscaling" {
  vpc_id             = var.vpc_id
  service_name       = "com.amazonaws.${data.aws_region.current.name}.autoscaling"
  vpc_endpoint_type  = "Interface"
  subnet_ids         = var.subnets
  security_group_ids = var.security_group_ids

  private_dns_enabled = true
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = var.vpc_id
  service_name      = "com.amazonaws.${data.aws_region.current.name}.s3"
  vpc_endpoint_type = "Gateway"
}