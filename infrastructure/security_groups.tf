# TODO - create one for Postgres and one For Redis instead of all to all
module "internal_security_group" {
  source = "terraform-aws-modules/security-group/aws"
  version = "4.8.0"

  name = "internal-${local.deployment_id}-sg"
  description = "Internal security group for AST deployment called ${local.deployment_id}."
  vpc_id = local.vpc_id

  ingress_cidr_blocks = [
    module.vpc.vpc_cidr_block]
  ingress_rules = [
    "all-all"]
  egress_rules = [
    "all-all"]

  create = var.sig.create
}

module "external_security_group" {
  source = "terraform-aws-modules/security-group/aws"
  version = "4.8.0"

  name = "external-${local.deployment_id}-sg"
  description = "External Security group for AST deployment called ${local.deployment_id}."
  vpc_id = local.vpc_id

  ingress_cidr_blocks = [
    "0.0.0.0/0"]
  ingress_rules = [
    "http-80-tcp",
    "https-443-tcp",
    "kubernetes-api-tcp",
    "ssh-tcp",
    "all-icmp"]
  egress_rules = [
    "all-all"]

  create = var.sig.create
}



locals {
  sig_k8s_to_dbs_id = var.sig.create == true ? module.internal_security_group.security_group_id : var.sig.existing_sig_k8s_to_dbs_id
}