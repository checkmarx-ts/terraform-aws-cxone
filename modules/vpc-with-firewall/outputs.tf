output "vpc_id" {
  value = aws_vpc.main.id
}

output "vpc_cidr_block" {
  value = var.primary_vpc_cidr
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

output "database_subnet_group_name" {
  value = aws_db_subnet_group.postgres.id
}

output "pod_subnets" {
  value = aws_subnet.pod.*.id
}

output "pod_subnet_info" {
  value = [
    for i in range(length(aws_subnet.pod.*)) :
    {
      "subnet_id"         = aws_subnet.pod[i].id
      "availability_zone" = aws_subnet.pod[i].availability_zone
    }
  ]
}
