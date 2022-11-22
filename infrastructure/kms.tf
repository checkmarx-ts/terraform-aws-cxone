resource "aws_kms_key" "eks" {
  count                   = var.kms.create ? 1 : 0
  description             = "EKS Secret Encryption Key"
  deletion_window_in_days = 7
  enable_key_rotation     = true
}


locals {
  kms_arn = var.kms.create == true ? aws_kms_key.eks[0].arn : var.kms.existing_kms_arn
}