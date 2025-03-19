data "aws_partition" "current" {}
data "aws_region" "current" {}
data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  azs             = slice(data.aws_availability_zones.available.names, 0, 2)
  vpc_cidr_blocks = [var.primary_cidr_block]

  # Here we are calculating the CIDRs for the subnets from the given primary VPC CIDR block. 
  # This VPC should not be used for production. It is optimized to reduce AWS costs at the expense of availability.
  # It is intended for dev/test workloads only. 
  # Cost optimizations: Single AZ NAT Gateway and AWS Network Firewall Endpoint for entire VPC
  #                     Only two AZs for private and database subnets to reduce cross AZ data transfer
  # Network Topology:
  #   Public Subnet:    /27  (single AZ) - contains NLB, NAT Gateway
  #   Firewall Subnet:  /28  (single AZ) - contains firewall endpoint
  #   Private Subnets:  /21 /21 (two AZ) - for EKS deployment
  #   Database Subnets: /22 /22 (two AZ) - for RDS, Elasticache, Opensearch deployment
  # Note about cidrsubnets newbits arguments:
  #   Subtracting the primary cidr size from the desired subnet size produces the 'newbits' value for the cidrsubnets 
  #   function to consistently create subnets of the desired size, regardless of the user provided 
  #   var.primary_cidr_block value. The primary_cidr_block must be at least a /19.
  primary_cidr_size = split("/", var.primary_cidr_block)[1]
  subnet_cidrs = cidrsubnets(var.primary_cidr_block,
    (27 - local.primary_cidr_size), # Public Subnet
    (28 - local.primary_cidr_size), # Firewall Subnet
    (21 - local.primary_cidr_size), # Private Subnet 1
    (21 - local.primary_cidr_size), # Private Subnet 2
    (22 - local.primary_cidr_size), # Database Subnet 1
  (22 - local.primary_cidr_size))   # Database Subnet 2
  public_subnet_cidr    = slice(local.subnet_cidrs, 0, 1)[0]
  firewall_subnet_cidr  = slice(local.subnet_cidrs, 1, 2)[0]
  private_subnet_cidrs  = slice(local.subnet_cidrs, 2, 4)
  database_subnet_cidrs = slice(local.subnet_cidrs, 4, 6)
}

#******************************************************************************
#   VPC & Subnets
#******************************************************************************
resource "aws_vpc" "main" {
  cidr_block           = var.primary_cidr_block
  enable_dns_hostnames = true # Required for EKS
  enable_dns_support   = true # Required for EKS

  tags = { Name = "${var.deployment_id}" }
}

resource "aws_subnet" "public" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = local.public_subnet_cidr
  availability_zone = local.azs[0]
  tags = {
    Name                                         = "${var.deployment_id} - public subnet ${local.azs[0]}"
    "kubernetes.io/cluster/${var.deployment_id}" = "shared"
    "kubernetes.io/role/elb"                     = "1"
    "karpenter.sh/discovery"                     = "${var.deployment_id}"
  }
}

resource "aws_subnet" "firewall" {
  count             = var.enable_firewall ? 1 : 0
  vpc_id            = aws_vpc.main.id
  cidr_block        = local.firewall_subnet_cidr
  availability_zone = local.azs[0]
  tags              = { Name = "${var.deployment_id} - firewall subnet ${local.azs[0]}" }
}

resource "aws_subnet" "private" {
  for_each          = { for idx, az in local.azs : az => idx }
  vpc_id            = aws_vpc.main.id
  cidr_block        = local.private_subnet_cidrs[each.value]
  availability_zone = each.key
  tags = {
    Name                                         = "${var.deployment_id} - private subnet ${each.key}"
    "kubernetes.io/cluster/${var.deployment_id}" = "shared"
    "kubernetes.io/role/internal-elb"            = "1"
    "karpenter.sh/discovery"                     = "${var.deployment_id}"
  }
}

resource "aws_subnet" "database" {
  for_each          = { for idx, az in local.azs : az => idx }
  vpc_id            = aws_vpc.main.id
  cidr_block        = local.database_subnet_cidrs[each.value]
  availability_zone = each.key
  tags              = { Name = "${var.deployment_id} - database subnet ${each.key}" }
}


#******************************************************************************
#   IGW & NAT Gateway
#******************************************************************************

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id
  tags = {
    Name = "${var.deployment_id}"
  }
}

resource "aws_eip" "nat" {
  domain     = "vpc"
  depends_on = [aws_internet_gateway.igw]
}

resource "aws_nat_gateway" "public" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public.id
  tags          = { Name = "NAT Gateway - ${var.deployment_id}" }
  depends_on    = [aws_internet_gateway.igw]
}

#******************************************************************************
#   Route Tables
#******************************************************************************

resource "aws_route_table" "igw" {
  vpc_id = aws_vpc.main.id
  tags   = { "Name" = "${var.deployment_id}-igw" }

  dynamic "route" {
    for_each = var.enable_firewall ? ["apply"] : []
    content {
      cidr_block      = local.public_subnet_cidr
      vpc_endpoint_id = [for ss in aws_networkfirewall_firewall.main[0].firewall_status[0].sync_states : ss.attachment[0].endpoint_id][0]
    }
  }

  dynamic "route" {
    for_each = { for idx, az in local.azs : az => idx if var.enable_firewall }
    content {
      cidr_block      = local.private_subnet_cidrs[route.value]
      vpc_endpoint_id = [for ss in aws_networkfirewall_firewall.main[0].firewall_status[0].sync_states : ss.attachment[0].endpoint_id][0]
    }
  }

  dynamic "route" {
    for_each = { for idx, az in local.azs : az => idx if var.enable_firewall }
    content {
      cidr_block      = local.database_subnet_cidrs[route.value]
      vpc_endpoint_id = [for ss in aws_networkfirewall_firewall.main[0].firewall_status[0].sync_states : ss.attachment[0].endpoint_id][0]
    }
  }

}

resource "aws_route_table_association" "igw" {
  gateway_id     = aws_internet_gateway.igw.id
  route_table_id = aws_route_table.igw.id
}


# Public Subnet Routing
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  tags   = { "Name" = "${var.deployment_id}-public" }

  route {
    cidr_block      = "0.0.0.0/0"
    gateway_id      = var.enable_firewall ? null : aws_internet_gateway.igw.id
    vpc_endpoint_id = var.enable_firewall ? [for ss in aws_networkfirewall_firewall.main[0].firewall_status[0].sync_states : ss.attachment[0].endpoint_id][0] : null
  }

  depends_on = [aws_networkfirewall_firewall.main]
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}


# Firewall Subnet Routing
resource "aws_route_table" "firewall" {
  count  = var.enable_firewall ? 1 : 0
  vpc_id = aws_vpc.main.id
  tags   = { "Name" = "${var.deployment_id}-firewall" }

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
}

resource "aws_route_table_association" "firewall" {
  count          = var.enable_firewall ? 1 : 0
  subnet_id      = aws_subnet.firewall[0].id
  route_table_id = aws_route_table.firewall[0].id
}

# Private Subnets Routing
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id
  tags   = { "Name" = "${var.deployment_id}-private" }
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.public.id
  }

  depends_on = [aws_networkfirewall_firewall.main]
}

resource "aws_route_table_association" "private" {
  for_each       = { for idx, az in local.azs : az => idx }
  subnet_id      = aws_subnet.private[each.key].id
  route_table_id = aws_route_table.private.id
}

