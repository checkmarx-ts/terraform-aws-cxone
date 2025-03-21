
locals {
  cluster_proxy_user_data_default = <<-EOT
    #!/bin/bash
    set -xe

    # Update system
    apt-get update -y
    apt-get upgrade -y

    # Install Squid
    apt-get install -y squid

    # Configure squid to allow traffic from specific CIDRs
    cat <<EOF >> /etc/squid/squid.conf

acl cxone_networkA src ${module.vpc.vpc_cidr_blocks}
http_access allow cxone_networkA

EOF

    # Restart squid
    systemctl restart squid
    systemctl enable squid
  EOT
}


module "cluster_proxy_security_group" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "~> 4.0"
  count   = var.cluster_proxy_enabled ? 1 : 0

  name        = "Cluster Proxy security group for deployment ${var.deployment_id}"
  description = "Security group for cluster proxy for deployment ${var.deployment_id}"
  vpc_id      = module.vpc.vpc_id

  ingress_cidr_blocks = module.vpc.vpc_cidr_blocks
  ingress_rules       = ["http-80-tcp", "https-443-tcp", "all-icmp", "ssh-tcp"]
  egress_rules        = ["all-all"]

}

module "cluster_proxy_ec2_instance" {
  source = "terraform-aws-modules/ec2-instance/aws"
  count  = var.cluster_proxy_enabled ? 1 : 0

  name                        = "${var.deployment_id}-cluster-proxy"
  ami                         = var.cluster_proxy_ami
  ignore_ami_changes          = true
  instance_type               = var.cluster_proxy_instance_type
  monitoring                  = false
  vpc_security_group_ids      = [module.cluster_proxy_security_group[0].security_group_id]
  subnet_id                   = module.vpc.public_subnets[0]
  create_eip                  = true
  user_data                   = var.cluster_proxy_user_data != null ? var.cluster_proxy_user_data : local.cluster_proxy_user_data_default

  create_iam_instance_profile = true
  iam_role_description        = "IAM role for cluster proxy EC2 instance"
  iam_role_policies = {
    AmazonSSMManagedInstanceCore = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
    AdministratorAccess          = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AdministratorAccess"
  }

  tags = {
    Terraform   = "true"
    Environment = "dev"
  }
}
