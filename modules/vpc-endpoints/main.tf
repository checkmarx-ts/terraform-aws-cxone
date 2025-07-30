
data "aws_region" "current" {}
resource "aws_vpc_endpoint" "ec2" {
  count              = var.create_ec2_endpoint ? 1 : 0
  vpc_id             = var.vpc_id
  service_name       = "com.amazonaws.${data.aws_region.current.region}.ec2"
  vpc_endpoint_type  = "Interface"
  subnet_ids         = var.subnets
  security_group_ids = var.security_group_ids

  private_dns_enabled = true

  tags = {
    Name = "${var.deployment_id}-ec2"
  }
}

resource "aws_vpc_endpoint" "ecr_api" {
  count              = var.create_ecr_api_endpoint ? 1 : 0
  vpc_id             = var.vpc_id
  service_name       = "com.amazonaws.${data.aws_region.current.region}.ecr.api"
  vpc_endpoint_type  = "Interface"
  subnet_ids         = var.subnets
  security_group_ids = var.security_group_ids

  private_dns_enabled = true

  tags = {
    Name = "${var.deployment_id}-ecr-api"
  }
}

# https://docs.aws.amazon.com/eks/latest/userguide/add-ons-images.html
resource "aws_vpc_endpoint" "ecr_dkr" {
  count              = var.create_ecr_dkr_endpoint ? 1 : 0
  vpc_id             = var.vpc_id
  service_name       = "com.amazonaws.${data.aws_region.current.region}.ecr.dkr"
  vpc_endpoint_type  = "Interface"
  subnet_ids         = var.subnets
  security_group_ids = var.security_group_ids

  private_dns_enabled = true
  tags = {
    Name = "${var.deployment_id}-ecr-dkr"
  }
}

resource "aws_vpc_endpoint" "ssm" {
  count              = var.create_ssm_endpoint ? 1 : 0
  vpc_id             = var.vpc_id
  service_name       = "com.amazonaws.${data.aws_region.current.region}.ssm"
  vpc_endpoint_type  = "Interface"
  subnet_ids         = var.subnets
  security_group_ids = var.security_group_ids

  private_dns_enabled = true
  tags = {
    Name = "${var.deployment_id}-ssm"
  }
}

resource "aws_vpc_endpoint" "ssmmessages" {
  count              = var.create_ssmmessages_endpoint ? 1 : 0
  vpc_id             = var.vpc_id
  service_name       = "com.amazonaws.${data.aws_region.current.region}.ssmmessages"
  vpc_endpoint_type  = "Interface"
  subnet_ids         = var.subnets
  security_group_ids = var.security_group_ids

  private_dns_enabled = true
  tags = {
    Name = "${var.deployment_id}-ssmmessages"
  }
}

resource "aws_vpc_endpoint" "ec2messages" {
  count              = var.create_ec2messages_endpoint ? 1 : 0
  vpc_id             = var.vpc_id
  service_name       = "com.amazonaws.${data.aws_region.current.region}.ec2messages"
  vpc_endpoint_type  = "Interface"
  subnet_ids         = var.subnets
  security_group_ids = var.security_group_ids

  private_dns_enabled = true
  tags = {
    Name = "${var.deployment_id}-ec2messages"
  }
}

resource "aws_vpc_endpoint" "kms" {
  count              = var.create_kms_endpoint ? 1 : 0
  vpc_id             = var.vpc_id
  service_name       = "com.amazonaws.${data.aws_region.current.region}.kms"
  vpc_endpoint_type  = "Interface"
  subnet_ids         = var.subnets
  security_group_ids = var.security_group_ids

  private_dns_enabled = true
  tags = {
    Name = "${var.deployment_id}-kms"
  }
}

resource "aws_vpc_endpoint" "logs" {
  count              = var.create_logs_endpoint ? 1 : 0
  vpc_id             = var.vpc_id
  service_name       = "com.amazonaws.${data.aws_region.current.region}.logs"
  vpc_endpoint_type  = "Interface"
  subnet_ids         = var.subnets
  security_group_ids = var.security_group_ids

  private_dns_enabled = true
  tags = {
    Name = "${var.deployment_id}-logs"
  }
}

resource "aws_vpc_endpoint" "sts" {
  count              = var.create_sts_endpoint ? 1 : 0
  vpc_id             = var.vpc_id
  service_name       = "com.amazonaws.${data.aws_region.current.region}.sts"
  vpc_endpoint_type  = "Interface"
  subnet_ids         = var.subnets
  security_group_ids = var.security_group_ids

  private_dns_enabled = true
  tags = {
    Name = "${var.deployment_id}-sts"
  }
}

resource "aws_vpc_endpoint" "elasticloadbalancing" {
  count              = var.create_elasticloadbalancing_endpoint ? 1 : 0
  vpc_id             = var.vpc_id
  service_name       = "com.amazonaws.${data.aws_region.current.region}.elasticloadbalancing"
  vpc_endpoint_type  = "Interface"
  subnet_ids         = var.subnets
  security_group_ids = var.security_group_ids

  private_dns_enabled = true
  tags = {
    Name = "${var.deployment_id}-elasticloadbalancing"
  }
}

# Used by Cluster Autoscaler
resource "aws_vpc_endpoint" "autoscaling" {
  count              = var.create_autoscaling_endpoint ? 1 : 0
  vpc_id             = var.vpc_id
  service_name       = "com.amazonaws.${data.aws_region.current.region}.autoscaling"
  vpc_endpoint_type  = "Interface"
  subnet_ids         = var.subnets
  security_group_ids = var.security_group_ids

  private_dns_enabled = true
  tags = {
    Name = "${var.deployment_id}-autoscaling"
  }
}

resource "aws_vpc_endpoint" "s3" {
  count             = var.create_s3_endpoint ? 1 : 0
  vpc_id            = var.vpc_id
  service_name      = "com.amazonaws.${data.aws_region.current.region}.s3"
  vpc_endpoint_type = "Gateway"
  tags = {
    Name = "${var.deployment_id}-s3"
  }
}