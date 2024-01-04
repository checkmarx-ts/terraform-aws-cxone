output "eks_cluster" {
  value = aws_security_group.eks_cluster.id
}

output "eks_node" {
  value = aws_security_group.eks_node.id
}

output "elasticache" {
  value = aws_security_group.elasticache.id
}

output "rds" {
  value = aws_security_group.rds.id
}
