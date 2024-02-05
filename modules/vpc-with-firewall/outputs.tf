output "vpc_id" {
  value = aws_vpc.main.id
}

output "vpc_cidr_block" {
  value = var.vpc_cidr
}

output "private_subnets" {
  value = aws_subnet.private.*.id
}

output "public_subnets" {
  value = aws_subnet.public.*.id
}

output "database_subnets" {
  value = aws_subnet.database.*.id
}

output "firewall_subnets" {
  value = aws_subnet.firewall.*.id
}