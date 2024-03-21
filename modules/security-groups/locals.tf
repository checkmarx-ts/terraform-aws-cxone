locals {
  internal_vpc_cidrs = concat([var.vpc_cidr], var.secondary_vpc_cidr != null ? [var.secondary_vpc_cidr] : [])
}