
locals {
  # to determine max pods when changing an instance type, check https://github.com/vantage-sh/ec2instances.info/issues/691
  launch_templates = {
    ast-app = {
      instance_type     = "m5zn.2xlarge" # c5.2xlarge
      max_pods          = 58
      additional_labels = "ast-app=true"
      taints            = ""
    }
    sast-engine = {
      instance_type     = "m5zn.2xlarge"
      max_pods          = "58"
      additional_labels = "sast-engine=true"
      taints            = "sast-engine=true:NoSchedule"
    }
    sast-engine-large = {
      instance_type     = "r5.2xlarge"
      max_pods          = "234"
      additional_labels = "sast-engine-large=true"
      taints            = "sast-engine-large=true:NoSchedule"
    }
    sast-engine-extra-large = {
      instance_type     = "r5.2xlarge"
      max_pods          = "58"
      additional_labels = "sast-engine-extra-large=true"
      taints            = "sast-engine-extra-large=true:NoSchedule"
    }
    sast-engine-xxl = {
      instance_type     = "r5.4xlarge"
      max_pods          = "234"
      additional_labels = "sast-engine-xxl=true"
      taints            = "sast-engine-xxl=true:NoSchedule"
    }
    kics-engine = {
      instance_type     = "m5a.xlarge" #c5.2xlarge
      max_pods          = "58"
      additional_labels = "kics-engine=true"
      taints            = "kics-engine=true:NoSchedule"
    }
    repostore = {
      instance_type     = "m5a.2xlarge" #c5.4xlarge
      max_pods          = "58"
      additional_labels = "repostore=true"
      taints            = "repostore=true:NoSchedule"
    }
    sca-source-resolver = {
      instance_type     = "m5zn.2xlarge" #c5.4xlarge
      max_pods          = "234"
      additional_labels = "service=sca-source-resolver"
      taints            = "service=sca-source-resolver:NoSchedule"
    }
  }
  ec2_key_name        = "stokes"
  self_managed_ami_id = data.aws_ssm_parameter.eks_ami_id.value #"ami-0b4a7d0197ce58ab4"
}

# Look up the EKS recommended AMI by EKS version (reference https://docs.aws.amazon.com/eks/latest/userguide/retrieve-ami-id.html)
# aws ssm get-parameter --name /aws/service/eks/optimized-ami/1.27/amazon-linux-2/recommended/image_id --region us-west-2 --query "Parameter.Value" --output text
data "aws_ssm_parameter" "eks_ami_id" {
  name = "/aws/service/eks/optimized-ami/1.29/amazon-linux-2/recommended/image_id"
}

resource "aws_launch_template" "self_managed" {
  for_each               = local.launch_templates
  name                   = "${var.deployment_id}-${each.key}"
  instance_type          = each.value.instance_type
  vpc_security_group_ids = [module.security_groups.eks_node]
  ebs_optimized          = true
  image_id               = local.self_managed_ami_id
  key_name               = local.ec2_key_name
  user_data = base64encode(<<-EOF
#!/bin/bash
set -ex
B64_CLUSTER_CA=${module.eks_cluster.cluster_certificate_authority_data}
API_SERVER_URL=${module.eks_cluster.cluster_endpoint}
K8S_CLUSTER_DNS_IP=172.20.0.10
/etc/eks/bootstrap.sh ${module.eks_cluster.cluster_name} --kubelet-extra-args '--node-labels=${each.value.additional_labels},eks.amazonaws.com/nodegroup-image=${local.self_managed_ami_id},eks.amazonaws.com/capacityType=ON_DEMAND,eks.amazonaws.com/nodegroup=${each.key} --max-pods=${each.value.max_pods} --register-with-taints=${each.value.taints}' --b64-cluster-ca $B64_CLUSTER_CA --apiserver-endpoint $API_SERVER_URL --dns-cluster-ip $K8S_CLUSTER_DNS_IP --use-max-pods false 
EOF
  )

  placement {
    tenancy = "dedicated"
  }

  iam_instance_profile {
    name = module.iam.eks_nodes_iam_role_name
  }

  monitoring {
    enabled = true
  }

  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size           = 250
      volume_type           = "gp3"
      iops                  = 3000
      throughput            = 125
      encrypted             = true
      delete_on_termination = true
    }
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    instance_metadata_tags      = "disabled"
    http_put_response_hop_limit = "2"
  }
}
