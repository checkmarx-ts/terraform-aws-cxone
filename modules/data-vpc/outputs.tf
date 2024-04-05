output "vpc_id" {
  value = var.vpc_id
}

output "pod_subnets" {
  value = [aws_subnet.pod1.id, aws_subnet.pod2.id, aws_subnet.pod3.id]
}

output "private_subnets" {
  value = var.existing_private_subnets
}

output "vpc_cidr_blocks" {
  value = [data.aws_vpc.main.cidr_block, var.secondary_vpc_cidr]
}

output "primary_vpc_cidr_block" {
  value = data.aws_vpc.main.cidr_block
}

output "secondary_vpc_cidr_block" {
  value = var.secondary_vpc_cidr
}

output "pod_subnet_info" {
  value = [
    {
      subnet_id         = aws_subnet.pod1.id
      availability_zone = aws_subnet.pod1.availability_zone
    },
    {
      subnet_id         = aws_subnet.pod2.id
      availability_zone = aws_subnet.pod2.availability_zone
    },
    {
      subnet_id         = aws_subnet.pod2.id
      availability_zone = aws_subnet.pod2.availability_zone
    }
  ]
}