module "vpc" {
  create_vpc = var.vpc.create

  source  = "terraform-aws-modules/vpc/aws"
  version = "3.12.0"

  name = local.deployment_id
  cidr = var.vpc_cidr

  azs = ["${var.aws_region}a", "${var.aws_region}b", "${var.aws_region}c"]


  private_subnets  = local.private_subnets
  public_subnets   = local.public_subnets
  database_subnets = local.database_subnets

  enable_nat_gateway     = true
  single_nat_gateway     = var.vpc.single_nat
  one_nat_gateway_per_az = var.vpc.nat_per_az

  enable_dns_hostnames = true
  enable_dns_support   = true

  public_subnet_tags = {
    "kubernetes.io/cluster/${local.deployment_id}" = "shared"
    "kubernetes.io/role/elb"                       = "1"
  }

  private_subnet_tags = {
    "kubernetes.io/cluster/${local.deployment_id}" = "shared"
    "kubernetes.io/role/internal-elb"              = "1"
  }

  enable_flow_log                      = true
  create_flow_log_cloudwatch_iam_role  = true
  create_flow_log_cloudwatch_log_group = true

}

locals {
  vpc_id          = var.vpc.create == true ? module.vpc.vpc_id : var.vpc.existing_vpc_id
  subnets         = var.vpc.create == true ? module.vpc.private_subnets : var.vpc.existing_subnet_ids
  db_subnets      = var.vpc.create == true ? module.vpc.database_subnets : var.vpc.existing_db_subnets
  db_subnet_group = var.vpc.create == true ? module.vpc.database_subnet_group_name : var.vpc.existing_db_subnets_group
}

# VPC S3 Gateway Endpoints
resource "aws_vpc_endpoint" "s3_gateway_private" {
  vpc_endpoint_type = "Gateway"
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_id            = local.vpc_id
  route_table_ids   = module.vpc.private_route_table_ids
  tags = {
      Name          = "${var.deployment_id}-s3-gateway-private"
  }
}