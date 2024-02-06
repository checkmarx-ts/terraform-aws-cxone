data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_region" "current" {}

data "aws_partition" "current" {}


locals {

  aws_azs = [
    data.aws_availability_zones.available.names[0],
    data.aws_availability_zones.available.names[1],
    data.aws_availability_zones.available.names[2],
  ]
  firewall_subnets = slice(cidrsubnets(var.vpc_cidr, 12, 12, 12, 6, 6, 6, 6, 6, 6, 3, 3, 3), 0, 3)  # /28 (14 hosts - only for firewall endpoints)
  public_subnets   = slice(cidrsubnets(var.vpc_cidr, 12, 12, 12, 6, 6, 6, 6, 6, 6, 3, 3, 3), 3, 6)  # /22 (1,106 hosts)
  database_subnets = slice(cidrsubnets(var.vpc_cidr, 12, 12, 12, 6, 6, 6, 6, 6, 6, 3, 3, 3), 6, 9)  # /22 (1,106 hosts)
  private_subnets  = slice(cidrsubnets(var.vpc_cidr, 12, 12, 12, 6, 6, 6, 6, 6, 6, 3, 3, 3), 9, 12) # /19 (8,128 hosts)

  az_count = min(length(local.aws_azs), length(local.firewall_subnets), var.maximum_azs)
}

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "Checkmarx One - ${var.deployment_id}"
  }
}

resource "aws_subnet" "firewall" {
  count             = local.az_count
  vpc_id            = aws_vpc.main.id
  cidr_block        = element(local.firewall_subnets, count.index)
  availability_zone = element(local.aws_azs, count.index)

  tags = {
    Name = "Firewall subnet ${count.index + 1} - ${var.deployment_id}"
  }
}

resource "aws_subnet" "private" {
  count             = local.az_count
  vpc_id            = aws_vpc.main.id
  cidr_block        = element(local.private_subnets, count.index)
  availability_zone = element(local.aws_azs, count.index)

  tags = {
    Name                                         = "Private subnet ${count.index + 1} - ${var.deployment_id}"
    "kubernetes.io/cluster/${var.deployment_id}" = "shared"
    "kubernetes.io/role/internal-elb"            = "1"
  }
}

resource "aws_subnet" "public" {
  count             = local.az_count
  vpc_id            = aws_vpc.main.id
  cidr_block        = element(local.public_subnets, count.index)
  availability_zone = element(local.aws_azs, count.index)

  tags = {
    Name                                         = "Public subnet ${count.index + 1} - ${var.deployment_id}"
    "kubernetes.io/cluster/${var.deployment_id}" = "shared"
    "kubernetes.io/role/elb"                     = "1"
  }
}

resource "aws_subnet" "database" {
  count             = local.az_count
  vpc_id            = aws_vpc.main.id
  cidr_block        = element(local.database_subnets, count.index)
  availability_zone = element(local.aws_azs, count.index)

  tags = {
    Name = "Database subnet ${count.index + 1} - ${var.deployment_id}"
  }
}

resource "aws_db_subnet_group" "postgres" {
  name       = var.deployment_id
  subnet_ids = aws_subnet.database.*.id

}



resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${var.deployment_id}"
  }
}

resource "aws_eip" "nat" {
  count = local.az_count
  vpc   = true
}


resource "aws_nat_gateway" "public" {
  count         = local.az_count
  allocation_id = element(aws_eip.nat.*.id, count.index)
  subnet_id     = element(aws_subnet.public.*.id, count.index)

  tags = {
    Name = "NAT Gateway ${count.index + 1} - ${var.deployment_id}"
  }

  # To ensure proper ordering, it is recommended to add an explicit dependency
  # on the Internet Gateway for the VPC.
  depends_on = [aws_internet_gateway.igw]
}

################
# IGW routes
################
resource "aws_route_table" "igw" {
  vpc_id = aws_vpc.main.id
  tags = {
    "Name" = "Route table for IGW Ingress in ${var.deployment_id}"
  }
}

resource "aws_route_table_association" "igw" {
  gateway_id     = aws_internet_gateway.igw.id
  route_table_id = aws_route_table.igw.id
}

resource "aws_route" "igw_public_routes" {
  count                  = local.az_count
  route_table_id         = aws_route_table.igw.id
  destination_cidr_block = element(local.public_subnets, count.index)
  vpc_endpoint_id        = element(flatten(aws_networkfirewall_firewall.main.firewall_status[0].sync_states[*].attachment[*].endpoint_id), count.index)
  timeouts {
    create = "5m"
  }
}

resource "aws_route" "igw_private_routes" {
  count                  = local.az_count
  route_table_id         = aws_route_table.igw.id
  destination_cidr_block = element(local.private_subnets, count.index)
  vpc_endpoint_id        = element(flatten(aws_networkfirewall_firewall.main.firewall_status[0].sync_states[*].attachment[*].endpoint_id), count.index)
  timeouts {
    create = "5m"
  }
}

resource "aws_route" "igw_database_routes" {
  count                  = local.az_count
  route_table_id         = aws_route_table.igw.id
  destination_cidr_block = element(local.database_subnets, count.index)
  vpc_endpoint_id        = element(flatten(aws_networkfirewall_firewall.main.firewall_status[0].sync_states[*].attachment[*].endpoint_id), count.index)
  timeouts {
    create = "5m"
  }
}


################
# Firewall routes
################
resource "aws_route_table" "firewall" {
  count  = local.az_count
  vpc_id = aws_vpc.main.id
  tags = {
    "Name" = "Route table for firewall subnet ${count.index} in ${var.deployment_id}"
  }
}

resource "aws_route_table_association" "firewall" {
  count          = local.az_count
  subnet_id      = element(aws_subnet.firewall.*.id, count.index)
  route_table_id = element(aws_route_table.firewall.*.id, count.index)
}

resource "aws_route" "firewall_igw" {
  count                  = local.az_count
  route_table_id         = element(aws_route_table.firewall.*.id, count.index)
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.igw.id
  timeouts {
    create = "5m"
  }
}



################
# Publiс routes
################
resource "aws_route_table" "public" {
  count  = local.az_count
  vpc_id = aws_vpc.main.id
  tags = {
    "Name" = "Route table for public subnet ${count.index} in ${var.deployment_id}"
  }
}

resource "aws_route_table_association" "public" {
  count          = local.az_count
  subnet_id      = element(aws_subnet.public.*.id, count.index)
  route_table_id = element(aws_route_table.public.*.id, count.index)
}

resource "aws_route" "public_firewall" {
  count                  = local.az_count
  route_table_id         = element(aws_route_table.public.*.id, count.index)
  destination_cidr_block = "0.0.0.0/0"
  vpc_endpoint_id        = element(flatten(aws_networkfirewall_firewall.main.firewall_status[0].sync_states[*].attachment[*].endpoint_id), count.index) # aws_internet_gateway.igw.id
  timeouts {
    create = "5m"
  }
}


#################
# Private routes
#################
resource "aws_route_table" "private" {
  count  = local.az_count
  vpc_id = aws_vpc.main.id
  tags = {
    "Name" = "Route table for private subnet ${count.index} in ${var.deployment_id}"
  }

  lifecycle {
    # When attaching VPN gateways it is common to define aws_vpn_gateway_route_propagation
    # resources that manipulate the attributes of the routing table (typically for the private subnets)
    ignore_changes = [propagating_vgws]
  }
}

resource "aws_route_table_association" "private" {
  count          = local.az_count
  subnet_id      = element(aws_subnet.private.*.id, count.index)
  route_table_id = element(aws_route_table.private.*.id, count.index)
}

resource "aws_route_table_association" "database" {
  count          = local.az_count
  subnet_id      = element(aws_subnet.database.*.id, count.index)
  route_table_id = element(aws_route_table.private.*.id, count.index)
}

resource "aws_route" "nat_gateway" {
  count = local.az_count

  route_table_id         = element(aws_route_table.private.*.id, count.index)
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = element(aws_nat_gateway.public.*.id, count.index)

  timeouts {
    create = "5m"
  }
}


#################
# Network Firewall
#################

resource "aws_networkfirewall_rule_group" "cxone" {
  capacity = 200
  name     = "${var.deployment_id}-cxone-deployment"
  type     = "STATEFUL"
  rules    = file("${path.module}/cxone.rules")

}

resource "aws_networkfirewall_firewall_policy" "main" {
  name = "${var.deployment_id}-checkmarxone"

  firewall_policy {
    policy_variables {
      rule_variables {
        key = "HOME_NET"
        ip_set {
          definition = [var.vpc_cidr]
        }
      }
    }
    stateless_default_actions          = ["aws:forward_to_sfe"]
    stateless_fragment_default_actions = ["aws:forward_to_sfe"]

    stateful_rule_group_reference {

      resource_arn = aws_networkfirewall_rule_group.cxone.arn

    }
  }
}

resource "aws_networkfirewall_firewall" "main" {
  name                = "${var.deployment_id}-checkmarxone"
  firewall_policy_arn = aws_networkfirewall_firewall_policy.main.arn
  vpc_id              = aws_vpc.main.id


  timeouts {
    create = "40m"
    update = "50m"
    delete = "1h"
  }

  dynamic "subnet_mapping" {
    for_each = aws_subnet.firewall.*.id
    content {
      subnet_id = subnet_mapping.value
    }
  }
}


# Firewall Logging

resource "aws_cloudwatch_log_group" "aws_nfw_alert" {
  name              = "${var.deployment_id}-aws-nfw-alert"
  retention_in_days = 14
}

resource "aws_cloudwatch_log_group" "aws_nfw_flow" {
  name              = "${var.deployment_id}-aws-nfw-flow"
  retention_in_days = 14

  tags = {
    Environment = "production"
    Application = "serviceA"
  }
}


resource "aws_networkfirewall_logging_configuration" "main" {
  firewall_arn = aws_networkfirewall_firewall.main.arn
  logging_configuration {
    log_destination_config {
      log_destination = {
        logGroup = aws_cloudwatch_log_group.aws_nfw_alert.name
      }
      log_destination_type = "CloudWatchLogs"
      log_type             = "ALERT"
    }
    log_destination_config {
      log_destination = {
        logGroup = aws_cloudwatch_log_group.aws_nfw_flow.name
      }
      log_destination_type = "CloudWatchLogs"
      log_type             = "FLOW"
    }
  }
}


output "aws_networkfirewall_firewall_endpoints" {
  value = element(flatten(aws_networkfirewall_firewall.main.firewall_status[0].sync_states[*].attachment[*].endpoint_id), 1)
}
