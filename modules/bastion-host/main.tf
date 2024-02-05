




data "aws_ami" "amazon_linux_23" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023*-x86_64"]
  }
}

module "ec2_instance" {
  source  = "terraform-aws-modules/ec2-instance/aws"

  name = "${var.deployment_id}-bastion"
  ami = data.aws_ami.amazon_linux_23.id
  instance_type          = var.instance_type
  key_name               = var.key_name
  monitoring             = false
  vpc_security_group_ids = [ module.security_group.security_group_id]
  subnet_id              = var.subnet_id

  user_data = <<-EOT
    #!/bin/bash
    echo "Hello Terraform!"
  EOT

  create_iam_instance_profile = true
  iam_role_description        = "IAM role for EC2 instance"
  iam_role_policies = {
    AmazonSSMManagedInstanceCore = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
  }

  tags = {
    Terraform   = "true"
    Environment = "dev"
  }
}

data "aws_subnet" "selected" {
  id = var.subnet_id
}

data "aws_vpc" "selected" {
  id = data.aws_subnet.selected.vpc_id
}

module "security_group" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "~> 4.0"

  name        = "Bastion host for deployment ${var.deployment_id}"
  description = "Security group for bastion host for deployment ${var.deployment_id}"
  vpc_id      = data.aws_subnet.selected.vpc_id

  ingress_cidr_blocks = concat(var.remote_management_cidrs, [data.aws_vpc.selected.cidr_block])
  ingress_rules       = ["http-80-tcp", "all-icmp", "ssh-tcp"]
  egress_rules        = ["all-all"]

}