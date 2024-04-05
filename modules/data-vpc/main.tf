data "aws_vpc" "main" {
  id = var.vpc_id
}
data "aws_subnet" "existing_1" {
  id = var.existing_private_subnets[0]
}
data "aws_subnet" "existing_2" {
  id = var.existing_private_subnets[1]
}
data "aws_subnet" "existing_3" {
  id = var.existing_private_subnets[2]
}

locals {
  # calculate 3 new networks within the secondary_vpc_cidr. Each new network will have 2 additional bits of subnet mask added from the provider secondary_vpc_cidr
  # Input cidr: /16     Output: 3 /18 networks (16,256 hosts each)
  # Input cidr: /17     Output: 3 /19 networks (8,128 hosts each)
  # Input cidr: /18     Output: 3 /20 networks (4064 hosts each)
  pod_subnet_cidrs = cidrsubnets(var.secondary_vpc_cidr, 2, 2, 2)
}

resource "aws_vpc_ipv4_cidr_block_association" "secondary_cidr" {
  vpc_id     = data.aws_vpc.main.id
  cidr_block = var.secondary_vpc_cidr
}


# Create the subnets for the pods
resource "aws_subnet" "pod1" {
  vpc_id            = data.aws_vpc.main.id
  cidr_block        = local.pod_subnet_cidrs[0]
  availability_zone = data.aws_subnet.existing_1.availability_zone
  depends_on        = [aws_vpc_ipv4_cidr_block_association.secondary_cidr]
  tags = {
    Name                                         = "${var.deployment_id} - EKS Pod subnet 1"
    "kubernetes.io/cluster/${var.deployment_id}" = "shared"
  }
}

resource "aws_subnet" "pod2" {
  vpc_id            = data.aws_vpc.main.id
  cidr_block        = local.pod_subnet_cidrs[1]
  availability_zone = data.aws_subnet.existing_2.availability_zone
  depends_on        = [aws_vpc_ipv4_cidr_block_association.secondary_cidr]
  tags = {
    Name                                         = "${var.deployment_id} - EKS Pod subnet 2"
    "kubernetes.io/cluster/${var.deployment_id}" = "shared"
  }
}

resource "aws_subnet" "pod3" {
  vpc_id            = data.aws_vpc.main.id
  cidr_block        = local.pod_subnet_cidrs[2]
  availability_zone = data.aws_subnet.existing_3.availability_zone
  depends_on        = [aws_vpc_ipv4_cidr_block_association.secondary_cidr]
  tags = {
    Name                                         = "${var.deployment_id} - EKS Pod subnet 3"
    "kubernetes.io/cluster/${var.deployment_id}" = "shared"
  }
}


resource "aws_ec2_tag" "karpenter_discovery" {
  for_each    = toset(var.existing_private_subnets)
  resource_id = each.value
  key         = "karpenter.sh/discovery"
  value       = var.deployment_id
}

resource "aws_ec2_tag" "cluster_autocaler_discovery" {
  for_each    = toset(var.existing_private_subnets)
  resource_id = each.value
  key         = "kubernetes.io/cluster/${var.deployment_id}"
  value       = "shared"
}

resource "aws_ec2_tag" "load_balancer_controller_discovery" {
  for_each    = toset(var.existing_private_subnets)
  resource_id = each.value
  key         = "kubernetes.io/role/elb"
  value       = "1"
}
