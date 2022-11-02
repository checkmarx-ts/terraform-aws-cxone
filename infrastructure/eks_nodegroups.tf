# Workaround for the issues that tags are not propagated from EKS managed node group to auto-scaling groups
#https://github.com/terraform-aws-modules/terraform-aws-eks/issues/1886#issuecomment-1044154307

# AST Default
module "ast_default"{
  source = "terraform-aws-modules/eks/aws//modules/eks-managed-node-group"

  name            = "${var.ast_nodes.name}-${local.deployment_id}"
  cluster_name    = local.deployment_id
  cluster_version = var.eks_cluster_version

  vpc_id     = local.vpc_id
  subnet_ids = local.subnets

  cluster_primary_security_group_id = module.eks.cluster_primary_security_group_id
  cluster_security_group_id = module.eks.cluster_security_group_id

  min_size     = var.ast_nodes.min_size
  max_size     = var.ast_nodes.max_size
  desired_size = var.ast_nodes.desired_size

  instance_types = var.ast_nodes.instance_types
  capacity_type  = var.ast_nodes.capacity_type

  metadata_options = {
    http_endpoint               = "enabled"
    http_tokens                 = "optional"
    instance_metadata_tags      = "disabled"
    http_put_response_hop_limit = "2"
  }

  block_device_mappings = {
    xvda = {
      device_name = var.ast_nodes.device_name
      ebs = {
        volume_size           = var.ast_nodes.disk_size_gib
        volume_type           = var.ast_nodes.volume_type
        iops                  = var.ast_nodes.disk_iops
        throughput            = var.ast_nodes.disk_throughput
        encrypted             = true
        delete_on_termination = true
      }
    }
  }

  tags = {
    Name = "${var.ast_nodes.name}-${local.deployment_id}"
  }
  
}
resource "aws_autoscaling_group_tag" "ast_default" {
  for_each = { for k, v in local.cluster_autoscaler_ast_default_asg_tags : k => v }

  autoscaling_group_name = module.ast_default.node_group_autoscaling_group_names[0]
  tag {
    key                 = each.value.tagKey
    value               = each.value.tagValue
    propagate_at_launch = false
  }
}

# sast_nodes-m5.2xlarge
module "ast_sast_engines" {
  source = "terraform-aws-modules/eks/aws//modules/eks-managed-node-group"

  name            = "${var.sast_nodes.name}-${local.deployment_id}"
  cluster_name    = local.deployment_id
  cluster_version = var.eks_cluster_version

  vpc_id     = local.vpc_id
  subnet_ids = local.subnets

  cluster_primary_security_group_id = module.eks.cluster_primary_security_group_id
  cluster_security_group_id = module.eks.cluster_security_group_id

  min_size     = var.sast_nodes.min_size
  max_size     = var.sast_nodes.max_size
  desired_size = var.sast_nodes.desired_size

  instance_types = var.sast_nodes.instance_types
  capacity_type  = var.sast_nodes.capacity_type

  metadata_options = {
    http_endpoint               = "enabled"
    http_tokens                 = "optional"
    instance_metadata_tags      = "disabled"
    http_put_response_hop_limit = "2"
  }

  block_device_mappings = {
    xvda = {
      device_name = var.sast_nodes_large.device_name
      ebs = {
        volume_size           = var.sast_nodes.disk_size_gib
        volume_type           = var.sast_nodes.volume_type
        iops                  = var.sast_nodes.disk_iops
        throughput            = var.sast_nodes.disk_throughput
        encrypted             = true
        delete_on_termination = true
      }
    }
  }

  labels = {
    "${var.sast_nodes.label_name}" = var.sast_nodes.label_value
  }

  taints = {
    dedicated = {
      key    = var.sast_nodes.key
      value  = var.sast_nodes.value
      effect = var.sast_nodes.effect
    }
  }
  
  tags = {
    Name  = "${var.sast_nodes.name}-${local.deployment_id}"
  }
}

resource "aws_autoscaling_group_tag" "ast_sast_engines" {
  for_each = { for k, v in local.cluster_autoscaler_ast_sast_engines_asg_tags : k => v }

  autoscaling_group_name = module.ast_sast_engines.node_group_autoscaling_group_names[0]
  tag {
    key                 = each.value.tagKey
    value               = each.value.tagValue
    propagate_at_launch = false
  }
}

# sast_nodes_medium-m6a.xlarge 
module "ast_sast_medium_engines" {
  source = "terraform-aws-modules/eks/aws//modules/eks-managed-node-group"

  name            = "${var.sast_nodes_medium.name}-${local.deployment_id}"
  cluster_name    = local.deployment_id
  cluster_version = var.eks_cluster_version

  vpc_id     = local.vpc_id
  subnet_ids = local.subnets

  cluster_primary_security_group_id = module.eks.cluster_primary_security_group_id
  cluster_security_group_id = module.eks.cluster_security_group_id

  min_size     = var.sast_nodes_medium.min_size
  max_size     = var.sast_nodes_medium.max_size
  desired_size = var.sast_nodes_medium.desired_size

  instance_types = var.sast_nodes_medium.instance_types
  capacity_type  = var.sast_nodes_medium.capacity_type

  metadata_options = {
    http_endpoint               = "enabled"
    http_tokens                 = "optional"
    instance_metadata_tags      = "disabled"
    http_put_response_hop_limit = "2"
  }

  block_device_mappings = {
    xvda = {
      device_name = var.sast_nodes_medium.device_name
      ebs = {
        volume_size           = var.sast_nodes_medium.disk_size_gib
        volume_type           = var.sast_nodes_medium.volume_type
        iops                  = var.sast_nodes_medium.disk_iops
        throughput            = var.sast_nodes_medium.disk_throughput
        encrypted             = true
        delete_on_termination = true
      }
    }
  }

  taints = {
    dedicated = {
      key    = var.sast_nodes_medium.key
      value  = var.sast_nodes_medium.value
      effect = var.sast_nodes_medium.effect
    }
  }
  
  labels = {
    "${var.sast_nodes_medium.label_name}" = var.sast_nodes_medium.label_value
  }
  tags = {
    Name = "${var.sast_nodes_medium.name}-${local.deployment_id}"
  }
}

resource "aws_autoscaling_group_tag" "ast_sast_medium_engines" {
  for_each = { for k, v in local.cluster_autoscaler_ast_sast_medium_engines_asg_tags : k => v }

  autoscaling_group_name = module.ast_sast_medium_engines.node_group_autoscaling_group_names[0]
  tag {
    key                 = each.value.tagKey
    value               = each.value.tagValue
    propagate_at_launch = false
  }
}

# sast_nodes_large-m5.2xlarge
module "ast_sast_large_engines" {
  source = "terraform-aws-modules/eks/aws//modules/eks-managed-node-group"

  name            = "${var.sast_nodes_large.name}-${local.deployment_id}"
  cluster_name    = local.deployment_id
  cluster_version = var.eks_cluster_version

  vpc_id     = local.vpc_id
  subnet_ids = local.subnets

  cluster_primary_security_group_id = module.eks.cluster_primary_security_group_id
  cluster_security_group_id = module.eks.cluster_security_group_id

  min_size     = var.sast_nodes_large.min_size
  max_size     = var.sast_nodes_large.max_size
  desired_size = var.sast_nodes_large.desired_size

  instance_types = var.sast_nodes_large.instance_types
  capacity_type  = var.sast_nodes_large.capacity_type

  metadata_options = {
    http_endpoint               = "enabled"
    http_tokens                 = "optional"
    instance_metadata_tags      = "disabled"
    http_put_response_hop_limit = "2"
  }

  block_device_mappings = {
    xvda = {
      device_name = var.sast_nodes_large.device_name
      ebs = {
        volume_size           = var.sast_nodes_large.disk_size_gib
        volume_type           = var.sast_nodes_large.volume_type
        iops                  = var.sast_nodes_large.disk_iops
        throughput            = var.sast_nodes_large.disk_throughput
        encrypted             = true
        delete_on_termination = true
      }
    }
  }

  taints = {
    dedicated = {
      key    = var.sast_nodes_large.key
      value  = var.sast_nodes_large.value
      effect = var.sast_nodes_large.effect
    }
  }
  
  labels = {
    "${var.sast_nodes_large.label_name}" = var.sast_nodes_large.label_value
  }
  tags = {
    Name = "${var.sast_nodes_large.name}-${local.deployment_id}"
  }
}

resource "aws_autoscaling_group_tag" "ast_sast_large_engines" {
  for_each = { for k, v in local.cluster_autoscaler_ast_sast_large_engines_asg_tags : k => v }

  autoscaling_group_name = module.ast_sast_large_engines.node_group_autoscaling_group_names[0]
  tag {
    key                 = each.value.tagKey
    value               = each.value.tagValue
    propagate_at_launch = false
  }
}

# sast_nodes_extra_large-r5.2xlarge
module "ast_sast_extra_large_engines" {
  source = "terraform-aws-modules/eks/aws//modules/eks-managed-node-group"

  name            = "${var.sast_nodes_extra_large.name}-${local.deployment_id}"
  cluster_name    = local.deployment_id
  cluster_version = var.eks_cluster_version

  vpc_id     = local.vpc_id
  subnet_ids = local.subnets

  cluster_primary_security_group_id = module.eks.cluster_primary_security_group_id
  cluster_security_group_id = module.eks.cluster_security_group_id

  min_size     = var.sast_nodes_extra_large.min_size
  max_size     = var.sast_nodes_extra_large.max_size
  desired_size = var.sast_nodes_extra_large.desired_size

  instance_types = var.sast_nodes_extra_large.instance_types
  capacity_type  = var.sast_nodes_extra_large.capacity_type

  metadata_options = {
    http_endpoint               = "enabled"
    http_tokens                 = "optional"
    instance_metadata_tags      = "disabled"
    http_put_response_hop_limit = "2"
  }

  block_device_mappings = {
    xvda = {
      device_name = var.sast_nodes_extra_large.device_name
      ebs = {
        volume_size           = var.sast_nodes_extra_large.disk_size_gib
        volume_type           = var.sast_nodes_extra_large.volume_type
        iops                  = var.sast_nodes_extra_large.disk_iops
        throughput            = var.sast_nodes_extra_large.disk_throughput
        encrypted             = true
        delete_on_termination = true
      }
    }
  }

  taints = {
    dedicated = {
      key    = var.sast_nodes_extra_large.key
      value  = var.sast_nodes_extra_large.value
      effect = var.sast_nodes_extra_large.effect
    }
  }
  labels = {
    "${var.sast_nodes_extra_large.label_name}" = var.sast_nodes_extra_large.label_value
  }
  tags = {
    Name="${var.sast_nodes_extra_large.name}-${local.deployment_id}"
  }
}
resource "aws_autoscaling_group_tag" "ast_sast_extra_large_engines" {
  for_each = { for k, v in local.cluster_autoscaler_ast_sast_extra_large_engines_asg_tags : k => v }

  autoscaling_group_name = module.ast_sast_extra_large_engines.node_group_autoscaling_group_names[0]
  tag {
    key                 = each.value.tagKey
    value               = each.value.tagValue
    propagate_at_launch = false
  }
}

# sast_nodes_xxl-r5.4xlarge
module "ast_sast_xxl_engines" {
  source = "terraform-aws-modules/eks/aws//modules/eks-managed-node-group"

  name            = "${var.sast_nodes_xxl.name}-${local.deployment_id}"
  cluster_name    = local.deployment_id
  cluster_version = var.eks_cluster_version

  vpc_id     = local.vpc_id
  subnet_ids = local.subnets

  cluster_primary_security_group_id = module.eks.cluster_primary_security_group_id
  cluster_security_group_id = module.eks.cluster_security_group_id

  min_size     = var.sast_nodes_xxl.min_size
  max_size     = var.sast_nodes_xxl.max_size
  desired_size = var.sast_nodes_xxl.desired_size

  instance_types = var.sast_nodes_xxl.instance_types
  capacity_type  = var.sast_nodes_xxl.capacity_type

  metadata_options = {
    http_endpoint               = "enabled"
    http_tokens                 = "optional"
    instance_metadata_tags      = "disabled"
    http_put_response_hop_limit = "2"
  }

  block_device_mappings = {
    xvda = {
      device_name = var.sast_nodes_xxl.device_name
      ebs = {
        volume_size           = var.sast_nodes_xxl.disk_size_gib
        volume_type           = var.sast_nodes_xxl.volume_type
        iops                  = var.sast_nodes_xxl.disk_iops
        throughput            = var.sast_nodes_xxl.disk_throughput
        encrypted             = true
        delete_on_termination = true
      }
    }
  }

  taints = {
    dedicated = {
      key    = var.sast_nodes_xxl.key
      value  = var.sast_nodes_xxl.value
      effect = var.sast_nodes_xxl.effect
    }
  }
  labels = {
    "${var.sast_nodes_xxl.label_name}" = var.sast_nodes_xxl.label_value
  }
  tags = {
    Name = "${var.sast_nodes_xxl.name}-${local.deployment_id}"
  }
}

resource "aws_autoscaling_group_tag" "ast_sast_xxl_engines" {
  for_each = { for k, v in local.cluster_autoscaler_ast_sast_xxl_engines_asg_tags : k => v }

  autoscaling_group_name = module.ast_sast_xxl_engines.node_group_autoscaling_group_names[0]
  tag {
    key                 = each.value.tagKey
    value               = each.value.tagValue
    propagate_at_launch = false
  }
}

# Kics
module "kics_nodes_engines" {
  source = "terraform-aws-modules/eks/aws//modules/eks-managed-node-group"

  name            = "${var.kics_nodes.name}-${local.deployment_id}"
  cluster_name    = local.deployment_id
  cluster_version = var.eks_cluster_version

  vpc_id     = local.vpc_id
  subnet_ids = local.subnets

  cluster_primary_security_group_id = module.eks.cluster_primary_security_group_id
  cluster_security_group_id = module.eks.cluster_security_group_id

  min_size     = var.kics_nodes.min_size
  max_size     = var.kics_nodes.max_size
  desired_size = var.kics_nodes.desired_size

  instance_types = var.kics_nodes.instance_types
  capacity_type  = var.kics_nodes.capacity_type

  metadata_options = {
    http_endpoint               = "enabled"
    http_tokens                 = "optional"
    instance_metadata_tags      = "disabled"
    http_put_response_hop_limit = "2"
  }

  block_device_mappings = {
    xvda = {
      device_name = var.kics_nodes.device_name
      ebs = {
        volume_size           = var.kics_nodes.disk_size_gib
        volume_type           = var.kics_nodes.volume_type
        iops                  = var.kics_nodes.disk_iops
        throughput            = var.kics_nodes.disk_throughput
        encrypted             = true
        delete_on_termination = true
      }
    }
  }

  taints = {
    dedicated = {
      key    = var.kics_nodes.key
      value  = var.kics_nodes.value
      effect = var.kics_nodes.effect
    }
  }
  labels = {
     "${var.kics_nodes.label_name}" = var.kics_nodes.label_value
  }
  tags = {
    Name="${var.kics_nodes.name}-${local.deployment_id}"
  }
}

resource "aws_autoscaling_group_tag" "kics_nodes_engines" {
  for_each = { for k, v in local.cluster_autoscaler_kics_nodes_engines_asg_tags : k => v }

  autoscaling_group_name = module.kics_nodes_engines.node_group_autoscaling_group_names[0]
  tag {
    key                 = each.value.tagKey
    value               = each.value.tagValue
    propagate_at_launch = false
  }
}

# MINIO GATEWAY
module "minio_gateway_nodes" {
  source = "terraform-aws-modules/eks/aws//modules/eks-managed-node-group"

  name            = "${var.minio_gateway_nodes.name}-${local.deployment_id}"
  cluster_name    = local.deployment_id
  cluster_version = var.eks_cluster_version

  vpc_id     = local.vpc_id
  subnet_ids = local.subnets

  cluster_primary_security_group_id = module.eks.cluster_primary_security_group_id
  cluster_security_group_id = module.eks.cluster_security_group_id

  min_size     = var.minio_gateway_nodes.min_size
  max_size     = var.minio_gateway_nodes.max_size
  desired_size = var.minio_gateway_nodes.desired_size

  instance_types = var.minio_gateway_nodes.instance_types
  capacity_type  = var.minio_gateway_nodes.capacity_type
  metadata_options = {
    http_endpoint               = "enabled"
    http_tokens                 = "optional"
    instance_metadata_tags      = "disabled"
    http_put_response_hop_limit = "2"
  }

  block_device_mappings = {
    xvda = {
      device_name = var.minio_gateway_nodes.device_name
      ebs = {
        volume_size           = var.minio_gateway_nodes.disk_size_gib
        volume_type           = var.minio_gateway_nodes.volume_type
        iops                  = var.minio_gateway_nodes.disk_iops
        throughput            = var.minio_gateway_nodes.disk_throughput
        encrypted             = true
        delete_on_termination = true
      }
    }
  }

  taints = {
    dedicated = {
      key    = var.minio_gateway_nodes.key
      value  = var.minio_gateway_nodes.value
      effect = var.minio_gateway_nodes.effect
    }
  }
  labels = {
     "${var.minio_gateway_nodes.label_name}" = var.minio_gateway_nodes.label_value
  }
  tags = {
    Name="${var.minio_gateway_nodes.name}-${local.deployment_id}"
  }
}

resource "aws_autoscaling_group_tag" "minio_gateway_nodes" {
  for_each = { for k, v in local.cluster_autoscaler_minio_gateway_nodes_asg_tags : k => v }

  autoscaling_group_name = module.minio_gateway_nodes.node_group_autoscaling_group_names[0]
  tag {
    key                 = each.value.tagKey
    value               = each.value.tagValue
    propagate_at_launch = false
  }
}

# REPOSTORE
module "repostore_nodes" {
  source = "terraform-aws-modules/eks/aws//modules/eks-managed-node-group"

  name            = "${var.repostore_nodes.name}-${local.deployment_id}"
  cluster_name    = local.deployment_id
  cluster_version = var.eks_cluster_version

  vpc_id     = local.vpc_id
  subnet_ids = local.subnets

  cluster_primary_security_group_id = module.eks.cluster_primary_security_group_id
  cluster_security_group_id = module.eks.cluster_security_group_id

  min_size     = var.repostore_nodes.min_size
  max_size     = var.repostore_nodes.max_size
  desired_size = var.repostore_nodes.desired_size

  instance_types = var.repostore_nodes.instance_types
  capacity_type  = var.repostore_nodes.capacity_type
  metadata_options = {
    http_endpoint               = "enabled"
    http_tokens                 = "optional"
    instance_metadata_tags      = "disabled"
    http_put_response_hop_limit = "2"
  }

  block_device_mappings = {
    xvda = {
      device_name = var.repostore_nodes.device_name
      ebs = {
        volume_size           = var.repostore_nodes.disk_size_gib
        volume_type           = var.repostore_nodes.volume_type
        iops                  = var.repostore_nodes.disk_iops
        throughput            = var.repostore_nodes.disk_throughput
        encrypted             = true
        delete_on_termination = true
      }
    }
  }

  taints = {
    dedicated = {
      key    = var.repostore_nodes.key
      value  = var.repostore_nodes.value
      effect = var.repostore_nodes.effect
    }
  }
  labels = {
     "${var.repostore_nodes.label_name}" = var.repostore_nodes.label_value
  }
  tags = {
    Name="${var.repostore_nodes.name}-${local.deployment_id}"
  }
}

# The Tags for cluster-autoscaler are created, but we will not use it for now.
# resource "aws_autoscaling_group_tag" "repostore_nodes" {
#   for_each = { for k, v in local.cluster_autoscaler_repostore_nodes_asg_tags : k => v }

#   autoscaling_group_name = module.repostore_nodes.node_group_autoscaling_group_names[0]
#   tag {
#     key                 = each.value.tagKey
#     value               = each.value.tagValue
#     propagate_at_launch = false
#   }
# }