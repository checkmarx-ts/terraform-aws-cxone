

locals {
  bastion_host_user_data_default = <<-EOT
    #!/bin/bash
    # Install kubectl
    sudo curl -O https://s3.us-west-2.amazonaws.com/amazon-eks/1.29.6/2024-07-12/bin/linux/amd64/kubectl
    sudo curl -O https://s3.us-west-2.amazonaws.com/amazon-eks/1.29.6/2024-07-12/bin/linux/amd64/kubectl.sha256
    #sha256sum -c kubectl.sha256 || exit 1
    sudo chmod +x ./kubectl
    sudo cp ./kubectl /usr/local/bin/kubectl

    # Set kubecontext
    aws eks update-kubeconfig --name ${var.deployment_id}
    
    #Install git
    sudo dnf install git -y

    # Set up docker
    sudo dnf install docker -y
    sudo systemctl start docker
    sudo systemctl enable docker
    sudo usermod -a -G docker $(whoami)

    # Install kots
    export REPL_USE_SUDO=y
    export REPL_INSTALL_PATH=/usr/local/bin
    sudo curl https://kots.io/install | bash
    
    # Install eksctl
    ARCH="$(uname -m | sed -e 's/x86_64/amd64/' -e 's/\(arm\)\(64\)\?.*/\1\2/' -e 's/aarch64$/arm64/')"
    PLATFORM=$(uname -s)_$ARCH
    sudo curl -sLO "https://github.com/eksctl-io/eksctl/releases/latest/download/eksctl_$PLATFORM.tar.gz"
    tar -xzf eksctl_$PLATFORM.tar.gz -C /tmp && rm -f eksctl_$PLATFORM.tar.gz
    sudo mv /tmp/eksctl /usr/local/bin

    # Install k9s
    curl -sLO "https://github.com/derailed/k9s/releases/download/v0.32.5/k9s_linux_amd64.rpm"
    sudo dnf install k9s_linux_amd64.rpm
  EOT
}

data "aws_ami" "amazon_linux_23" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023*-x86_64"]
  }
}

module "ec2_instance" {
  source = "terraform-aws-modules/ec2-instance/aws"
  count  = var.bastion_host_enabled ? 1 : 0

  name                        = "${var.deployment_id}-bastion"
  ami                         = data.aws_ami.amazon_linux_23.id
  ignore_ami_changes          = true
  instance_type               = var.bastion_host_instance_type
  key_name                    = var.bastion_host_key_name
  monitoring                  = false
  vpc_security_group_ids      = [module.bastion_security_group[0].security_group_id]
  subnet_id                   = module.vpc.public_subnets[0]
  associate_public_ip_address = true
  user_data                   = var.bastion_host_user_data != null ? var.bastion_host_user_data : local.bastion_host_user_data_default

  create_iam_instance_profile = true
  iam_role_description        = "IAM role for EC2 instance"
  iam_role_policies = {
    AmazonSSMManagedInstanceCore = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
    AdministratorAccess          = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AdministratorAccess"
  }

  ebs_block_device = [
    {
      device_name = "/dev/xvda"
      volume_type = "gp3"
      volume_size = var.bastion_host_volume_size
      encrypted   = true
      kms_key_id  = aws_kms_key.main.arn

    }
  ]

  tags = {
    Terraform   = "true"
    Environment = "dev"
  }
}


module "bastion_security_group" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "~> 4.0"
  count   = var.bastion_host_enabled ? 1 : 0

  name        = "Bastion host for deployment ${var.deployment_id}"
  description = "Security group for bastion host for deployment ${var.deployment_id}"
  vpc_id      = module.vpc.vpc_id

  ingress_cidr_blocks = concat(var.bastion_host_remote_management_cidrs, module.vpc.vpc_cidr_blocks)
  ingress_rules       = ["http-80-tcp", "all-icmp", "ssh-tcp"]
  egress_rules        = ["all-all"]

}
