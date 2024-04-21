output "vpc_id" {
  description = "The id of the VPC"
  value       = aws_vpc.main.id
}

output "vpc_cidr_blocks" {
  description = "The VPC CIDR blocks of the VPC"
  value       = local.vpc_cidr_blocks
}

output "public_subnets" {
  description = "List of public subnet IDs in the VPC"
  value       = [aws_subnet.public.id]
}

output "firewall_subnets" {
  description = "List of firewall subnet IDs in the VPC"
  value       = var.enable_firewall ? aws_subnet.firewall[0].id : null
}

output "private_subnets" {
  description = "List of private subnet IDs in the VPC"
  value       = [for s in aws_subnet.private : s.id]
}

output "pod_subnets" {
  description = "List of pod subnet IDs in the VPC"
  value       = [for s in aws_subnet.pod : s.id]
}

output "database_subnets" {
  description = "List of database subnet IDs in the VPC"
  value       = [for s in aws_subnet.database : s.id]
}

output "pod_subnet_info" {
  description = "List of map of pod subnets including `subnet_id` and `availability_zone`. Useful for creating ENIConfigs for [EKS Custom Networking](https://docs.aws.amazon.com/eks/latest/userguide/cni-custom-network.html)."
  value = [for s in aws_subnet.pod : {
    subnet_id         = s.id
    availability_zone = s.availability_zone
  }]
}

output "azs" {
  description = "The Availability Zones deployed into"
  value       = local.azs
}
