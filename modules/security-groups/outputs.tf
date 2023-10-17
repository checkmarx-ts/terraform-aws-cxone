output "internal" {
  value = aws_security_group.internal.id
}

output "external" {
  value = aws_security_group.external.id
}

output "elasticache" {
  value = aws_security_group.elasticache.id
}

output "rds" {
  value = aws_security_group.rds.id
}
