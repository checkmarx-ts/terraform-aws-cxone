module "vpc_endpoint_security_group" {
  create              = var.create_interface_endpoints
  source              = "terraform-aws-modules/security-group/aws"
  version             = "5.1.2"
  name                = "${var.deployment_id}-vpc-endpoints"
  description         = "VPC endpoint security group for Checkmarx One deployment named ${var.deployment_id}"
  vpc_id              = aws_vpc.main.id
  ingress_cidr_blocks = local.vpc_cidr_blocks
  ingress_rules       = ["https-443-tcp"]
}

resource "aws_vpc_endpoint" "interface" {
  for_each            = { for idx, endpoint in var.interface_vpc_endpoints : endpoint => idx if var.create_interface_endpoints }
  vpc_id              = aws_vpc.main.id
  subnet_ids          = [for s in aws_subnet.private : s.id]
  service_name        = "com.amazonaws.${data.aws_region.current.name}.${each.key}"
  vpc_endpoint_type   = "Interface"
  security_group_ids  = [module.vpc_endpoint_security_group.security_group_id]
  private_dns_enabled = true
  tags                = { Name = "${var.deployment_id}-${each.key}-vpc-endpoint" }
}

resource "aws_vpc_endpoint" "s3_gateway_private" {
  count             = var.create_s3_endpoint ? 1 : 0
  vpc_endpoint_type = "Gateway"
  service_name      = "com.amazonaws.${data.aws_region.current.name}.s3"
  vpc_id            = aws_vpc.main.id
  route_table_ids   = [aws_route_table.private.id, aws_route_table.public.id]
  tags              = { Name = "${var.deployment_id}-s3-vpc-endpoint" }
}
