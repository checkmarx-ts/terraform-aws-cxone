
module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "19.17.2"

  cluster_name    = var.deployment_id
  cluster_version = var.eks_cluster_version

  cluster_enabled_log_types = ["audit", "api", "authenticator", "scheduler"]

  cluster_endpoint_private_access = var.enable_private_endpoint
  cluster_endpoint_public_access  = var.enable_public_endpoint

  vpc_id     = var.vpc_id
  subnet_ids = var.subnet_ids

  enable_irsa = true

  aws_auth_roles = [
    {
      rolearn  = var.cluster_access_iam_role_arn
      username = "AWSAdministratorAccess:{{SessionName}}"
      groups   = ["system:masters"]
    }
  ]

  cluster_addons = {
    coredns = {
      most_recent = true
    }
    kube-proxy = {
      most_recent = true
    }
    vpc-cni = {
      most_recent = true
    }
    aws-ebs-csi-driver = {
      most_recent = true
    }
  }


  create_kms_key = false
  cluster_encryption_config = {
    "resources"      = ["secrets"]
    provider_key_arn = var.eks_kms_key_arn
  }

  # aws-auth configmap
  create_aws_auth_configmap = false
  manage_aws_auth_configmap = true

  # EKS Managed Node Group(s)
  eks_managed_node_group_defaults = {
    #vpc_security_group_ids          = var.default_security_group_ids
    use_name_prefix                 = false
    iam_role_use_name_prefix        = false
    launch_template_use_name_prefix = false
    cluster_name                    = var.deployment_id
    cluster_version                 = var.eks_cluster_version
    subnet_ids                      = var.subnet_ids
    iam_role_additional_policies = {
      # AmazonEBSCSIDriverPolicy is required by Kots
      AmazonEBSCSIDriverPolicy = "arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"
    }

    metadata_options = {
      http_endpoint               = "enabled"
      http_tokens                 = "required"
      instance_metadata_tags      = "disabled"
      http_put_response_hop_limit = "2"
    }
  }

  eks_managed_node_groups = {

    default = {
      name                 = var.default_node_group.name
      launch_template_name = "${var.default_node_group.name}-${var.deployment_id}"
      iam_role_name        = "${var.default_node_group.name}-${var.deployment_id}"
      min_size             = var.default_node_group.min_size
      max_size             = var.default_node_group.max_size
      desired_size         = var.default_node_group.desired_size
      instance_types       = var.default_node_group.instance_types
      capacity_type        = var.default_node_group.capacity_type

      block_device_mappings = {
        xvda = {
          device_name = var.default_node_group.device_name
          ebs = {
            volume_size           = var.default_node_group.disk_size_gib
            volume_type           = var.default_node_group.volume_type
            iops                  = var.default_node_group.disk_iops
            throughput            = var.default_node_group.disk_throughput
            encrypted             = true
            delete_on_termination = true
          }
        }
      }

      tags = {
        Name = "${var.default_node_group.name}-${var.deployment_id}"
      }
    }

    kics = {
      name                 = var.kics_nodes.name
      launch_template_name = "${var.kics_nodes.name}-${var.deployment_id}"
      iam_role_name        = "${var.kics_nodes.name}-${var.deployment_id}"
      min_size             = var.kics_nodes.min_size
      max_size             = var.kics_nodes.max_size
      desired_size         = var.kics_nodes.desired_size
      instance_types       = var.kics_nodes.instance_types
      capacity_type        = var.kics_nodes.capacity_type

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
        Name = "${var.kics_nodes.name}-${var.deployment_id}"
      }
    }

    metrics = {
      name                 = var.metrics_nodes.name
      launch_template_name = "${var.metrics_nodes.name}-${var.deployment_id}"
      iam_role_name        = "${var.metrics_nodes.name}-${var.deployment_id}"
      min_size             = var.metrics_nodes.min_size
      max_size             = var.metrics_nodes.max_size
      desired_size         = var.metrics_nodes.desired_size
      instance_types       = var.metrics_nodes.instance_types
      capacity_type        = var.metrics_nodes.capacity_type

      block_device_mappings = {
        xvda = {
          device_name = var.metrics_nodes.device_name
          ebs = {
            volume_size           = var.metrics_nodes.disk_size_gib
            volume_type           = var.metrics_nodes.volume_type
            iops                  = var.metrics_nodes.disk_iops
            throughput            = var.metrics_nodes.disk_throughput
            encrypted             = true
            delete_on_termination = true
          }
        }
      }

      taints = {
        dedicated = {
          key    = var.metrics_nodes.key
          value  = var.metrics_nodes.value
          effect = var.metrics_nodes.effect
        }
      }

      labels = {
        "${var.metrics_nodes.label_name}" = "${var.metrics_nodes.label_value}"
      }

      tags = {
        Name = "${var.metrics_nodes.name}-${var.deployment_id}"
      }
    }

    minio = {
      name                 = var.minio_gateway_nodes.name
      launch_template_name = "${var.minio_gateway_nodes.name}-${var.deployment_id}"
      iam_role_name        = "${var.minio_gateway_nodes.name}-${var.deployment_id}"
      min_size             = var.minio_gateway_nodes.min_size
      max_size             = var.minio_gateway_nodes.max_size
      desired_size         = var.minio_gateway_nodes.desired_size
      instance_types       = var.minio_gateway_nodes.instance_types
      capacity_type        = var.minio_gateway_nodes.capacity_type

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
        Name = "${var.minio_gateway_nodes.name}-${var.deployment_id}"
      }
    }

    reports = {
      name                 = var.reports_nodes.name
      launch_template_name = "${var.reports_nodes.name}-${var.deployment_id}"
      iam_role_name        = "${var.reports_nodes.name}-${var.deployment_id}"
      min_size             = var.reports_nodes.min_size
      max_size             = var.reports_nodes.max_size
      desired_size         = var.reports_nodes.desired_size
      instance_types       = var.reports_nodes.instance_types
      capacity_type        = var.reports_nodes.capacity_type

      block_device_mappings = {
        xvda = {
          device_name = var.reports_nodes.device_name
          ebs = {
            volume_size           = var.reports_nodes.disk_size_gib
            volume_type           = var.reports_nodes.volume_type
            iops                  = var.reports_nodes.disk_iops
            throughput            = var.reports_nodes.disk_throughput
            encrypted             = true
            delete_on_termination = true
          }
        }
      }

      taints = {
        dedicated = {
          key    = var.reports_nodes.key
          value  = var.reports_nodes.value
          effect = var.reports_nodes.effect
        }
      }

      labels = {
        "${var.reports_nodes.label_name}" = "${var.reports_nodes.label_value}"
      }

      tags = {
        Name = "${var.reports_nodes.name}-${var.deployment_id}"
      }
    }

    repostore = {
      name                 = var.repostore_nodes.name
      launch_template_name = "${var.repostore_nodes.name}-${var.deployment_id}"
      iam_role_name        = "${var.repostore_nodes.name}-${var.deployment_id}"
      min_size             = var.repostore_nodes.min_size
      max_size             = var.repostore_nodes.max_size
      desired_size         = var.repostore_nodes.desired_size
      instance_types       = var.repostore_nodes.instance_types
      capacity_type        = var.repostore_nodes.capacity_type

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
        Name = "${var.repostore_nodes.name}-${var.deployment_id}"
      }
    }

    sast_engines = {
      name                 = var.sast_nodes.name
      launch_template_name = "${var.sast_nodes.name}-${var.deployment_id}"
      iam_role_name        = "${var.sast_nodes.name}-${var.deployment_id}"
      min_size             = var.sast_nodes.min_size
      max_size             = var.sast_nodes.max_size
      desired_size         = var.sast_nodes.desired_size
      instance_types       = var.sast_nodes.instance_types
      capacity_type        = var.sast_nodes.capacity_type

      block_device_mappings = {
        xvda = {
          device_name = var.sast_nodes.device_name
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
        Name = "${var.sast_nodes.name}-${var.deployment_id}"
      }
    }

    sast_engines_large = {
      name                 = var.sast_nodes_large.name
      launch_template_name = "${var.sast_nodes_large.name}-${var.deployment_id}"
      iam_role_name        = "${var.sast_nodes_large.name}-${var.deployment_id}"
      min_size             = var.sast_nodes_large.min_size
      max_size             = var.sast_nodes_large.max_size
      desired_size         = var.sast_nodes_large.desired_size
      instance_types       = var.sast_nodes_large.instance_types
      capacity_type        = var.sast_nodes_large.capacity_type

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
        Name = "${var.sast_nodes_large.name}-${var.deployment_id}"
      }

    }

    sast_engines_xl = {
      name                 = var.sast_nodes_extra_large.name
      launch_template_name = "${var.sast_nodes_extra_large.name}-${var.deployment_id}"
      iam_role_name        = "${var.sast_nodes_extra_large.name}-${var.deployment_id}"
      min_size             = var.sast_nodes_extra_large.min_size
      max_size             = var.sast_nodes_extra_large.max_size
      desired_size         = var.sast_nodes_extra_large.desired_size
      instance_types       = var.sast_nodes_extra_large.instance_types
      capacity_type        = var.sast_nodes_extra_large.capacity_type

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
        Name = "${var.sast_nodes_extra_large.name}-${var.deployment_id}"
      }
    }

    sast_engines_2xl = {
      name                 = var.sast_nodes_xxl.name
      launch_template_name = "${var.sast_nodes_xxl.name}-${var.deployment_id}"
      iam_role_name        = "${var.sast_nodes_xxl.name}-${var.deployment_id}"
      min_size             = var.sast_nodes_xxl.min_size
      max_size             = var.sast_nodes_xxl.max_size
      desired_size         = var.sast_nodes_xxl.desired_size
      instance_types       = var.sast_nodes_xxl.instance_types
      capacity_type        = var.sast_nodes_xxl.capacity_type

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
        Name = "${var.sast_nodes_xxl.name}-${var.deployment_id}"
      }
    }

    sca = {
      name                 = var.sca_nodes.name
      launch_template_name = "${var.sca_nodes.name}-${var.deployment_id}"
      iam_role_name        = "${var.sca_nodes.name}-${var.deployment_id}"
      min_size             = var.sca_nodes.min_size
      max_size             = var.sca_nodes.max_size
      desired_size         = var.sca_nodes.desired_size
      instance_types       = var.sca_nodes.instance_types
      capacity_type        = var.sca_nodes.capacity_type

      block_device_mappings = {
        xvda = {
          device_name = var.sca_nodes.device_name
          ebs = {
            volume_size           = var.sca_nodes.disk_size_gib
            volume_type           = var.sca_nodes.volume_type
            iops                  = var.sca_nodes.disk_iops
            throughput            = var.sca_nodes.disk_throughput
            encrypted             = true
            delete_on_termination = true
          }
        }
      }

      taints = {
        dedicated = {
          key    = var.sca_nodes.key
          value  = var.sca_nodes.value
          effect = var.sca_nodes.effect
        }
      }

      labels = {
        "${var.sca_nodes.label_name}" = "${var.sca_nodes.label_value}"
      }

      tags = {
        Name = "${var.sca_nodes.name}-${var.deployment_id}"
      }
    }

    dast = {
      name                 = var.dast_nodes.name
      launch_template_name = "${var.dast_nodes.name}-${var.deployment_id}"
      iam_role_name        = "${var.dast_nodes.name}-${var.deployment_id}"
      min_size             = var.dast_nodes.min_size
      max_size             = var.dast_nodes.max_size
      desired_size         = var.dast_nodes.desired_size
      instance_types       = var.dast_nodes.instance_types
      capacity_type        = var.dast_nodes.capacity_type

      block_device_mappings = {
        xvda = {
          device_name = var.dast_nodes.device_name
          ebs = {
            volume_size           = var.dast_nodes.disk_size_gib
            volume_type           = var.dast_nodes.volume_type
            iops                  = var.dast_nodes.disk_iops
            throughput            = var.dast_nodes.disk_throughput
            encrypted             = true
            delete_on_termination = true
          }
        }
      }

      taints = {
        dedicated = {
          key    = var.dast_nodes.key
          value  = var.dast_nodes.value
          effect = var.dast_nodes.effect
        }
      }

      labels = {
        "${var.dast_nodes.label_name}" = "${var.dast_nodes.label_value}"
      }

      tags = {
        Name = "${var.dast_nodes.name}-${var.deployment_id}"
      }
    }

  }
}



# Policy to Allow Minio Nodegroup to aceess the S3 Buckets
resource "aws_iam_policy" "ast_s3_buckets_policy" {
  name = "${var.deployment_id}-eks-ng-minio-gateway-S3"
  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Action" : [
          "s3:*"
        ],
        "Effect" : "Allow",
        "Resource" : [
          "arn:aws:s3:::*${lower(var.s3_bucket_name_suffix)}",
          "arn:aws:s3:::*${lower(var.s3_bucket_name_suffix)}/*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ast_s3_buckets_policy_attachment" {
  role       = module.eks.eks_managed_node_groups.minio.iam_role_name
  policy_arn = aws_iam_policy.ast_s3_buckets_policy.arn
}

# Set GP3 as the default storage class
resource "kubernetes_storage_class" "storage_class_gp3" {
  depends_on = [
    module.eks.aws_eks_addon
  ]
  metadata {
    name = "gp3"
    annotations = {
      "storageclass.kubernetes.io/is-default-class" = "true"
    }
  }
  storage_provisioner    = "ebs.csi.aws.com"
  volume_binding_mode    = "WaitForFirstConsumer"
  allow_volume_expansion = "true"
  parameters = {
    type   = "gp3"
    fstype = "xfs"
  }
}
# AWS STORAGE CLASS GP2
resource "kubernetes_annotations" "gp2" {
  depends_on = [
    module.eks.aws_eks_addon
  ]
  api_version = "storage.k8s.io/v1"
  kind        = "StorageClass"
  metadata {
    name = "gp2"
  }
  annotations = {
    "storageclass.kubernetes.io/is-default-class" = "false"
  }
  force = true
}