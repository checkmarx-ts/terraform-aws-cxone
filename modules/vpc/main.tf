data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_region" "current" {}


locals {
  number_of_azs    = 2
  aws_azs          = slice(data.aws_availabilty_zones.available.names, 0, local.number_of_azs)
  private_subnets  = slice(cidrsubnets(var.vpc_cidr, 2, 2, 2, 5, 5, 5, 6, 6, 6), 0, 3) # VPC=/16: /18 16,256; 
  public_subnets   = slice(cidrsubnets(var.vpc_cidr, 2, 2, 2, 5, 5, 5, 6, 6, 6), 6, 9) # VPC=/16: /21  2,032; 
  database_subnets = slice(cidrsubnets(var.vpc_cidr, 2, 2, 2, 5, 5, 5, 6, 6, 6), 3, 6) # VPC=/16: /22  1,016; 
}

module "vpc" {

  source  = "terraform-aws-modules/vpc/aws"
  version = "5.7.0"

  name = var.deployment_id
  cidr = var.vpc_cidr

  azs = local.aws_azs

  private_subnets  = local.private_subnets
  public_subnets   = local.public_subnets
  database_subnets = local.database_subnets

  enable_nat_gateway     = true
  single_nat_gateway     = var.single_nat
  one_nat_gateway_per_az = var.nat_per_az

  enable_dns_hostnames = true
  enable_dns_support   = true

  public_subnet_tags = {
    "karpenter.sh/discovery"                     = "${var.deployment_id}"
    "kubernetes.io/cluster/${var.deployment_id}" = "shared"
    "kubernetes.io/role/elb"                     = "1"
  }

  private_subnet_tags = {
    "karpenter.sh/discovery"                     = "${var.deployment_id}"
    "kubernetes.io/cluster/${var.deployment_id}" = "shared"
    "kubernetes.io/role/internal-elb"            = "1"
  }

  enable_flow_log                      = true
  create_flow_log_cloudwatch_iam_role  = true
  create_flow_log_cloudwatch_log_group = true

}



# VPC S3 Gateway Endpoints
resource "aws_vpc_endpoint" "s3_gateway_private" {
  vpc_endpoint_type = "Gateway"
  service_name      = "com.amazonaws.${data.aws_region.current.region}.s3"
  vpc_id            = module.vpc.vpc_id
  route_table_ids   = module.vpc.private_route_table_ids
  tags = {
    Name = "${var.deployment_id}-s3-gateway-private"
  }
}