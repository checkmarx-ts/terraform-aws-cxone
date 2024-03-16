data "aws_region" "current" {}

data "aws_eks_cluster" "cluster" {
  name       = module.eks.cluster_name
  depends_on = [module.eks.cluster_name]
}

module "cluster-externaldns" {
  depends_on = [module.eks]
  source = "../cluster-externaldns"

  deployment_id     = var.deployment_id
  oidc_provider_arn = module.eks.oidc_provider_arn
}

module "cluster-loadbalancer" {
  depends_on = [module.eks]
  source = "../cluster-loadbalancer"

  deployment_id     = var.deployment_id
  oidc_provider_arn = module.eks.oidc_provider_arn
}

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

  create_cluster_security_group = false
  cluster_security_group_id     = var.cluster_security_group_id

  create_node_security_group = false
  node_security_group_id     = var.node_security_group_id

  enable_irsa = true

  tags = {
    "karpenter.sh/discovery" = var.deployment_id
  }

  aws_auth_roles = [
    {
      rolearn  = var.cluster_access_iam_role_arn
      username = "AWSAdministratorAccess:{{SessionName}}"
      groups   = ["system:masters"]
    },
    {
      rolearn  = module.karpenter.iam_role_arn
      username = "system:node:{{EC2PrivateDNSName}}"
      groups = [
        "system:bootstrappers",
        "system:nodes"
      ]
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
    create_launch_template          = false 
    use_custom_launch_template      = false 
    vpc_security_group_ids          = var.default_security_group_ids
    use_name_prefix                 = false
    iam_role_use_name_prefix        = false
    launch_template_use_name_prefix = false
    cluster_name                    = var.deployment_id
    cluster_version                 = var.eks_cluster_version
    subnet_ids                      = var.subnet_ids
    create_iam_role                 = false
    iam_role_arn                    = var.nodegroup_iam_role_arn


    metadata_options = {
      http_endpoint               = "enabled"
      http_tokens                 = "required"
      instance_metadata_tags      = "disabled"
      http_put_response_hop_limit = "2"
    }
  }

  eks_managed_node_groups = {
    
    default = {
      name                 = "${var.deployment_id}-managed-ng"
      min_size             = 2
      max_size             = 2
      desired_size         = 2
      instance_types       = ["c5.2xlarge"]
      capacity_type        = "ON_DEMAND"

      block_device_mappings = {
        xvda = {
          device_name = "/dev/xvda"
          ebs = {
            volume_size           = 200
            volume_type           = "gp3"
            iops                  = 3000
            throughput            = 125
            encrypted             = true
            delete_on_termination = true
          }
        }
      }

      labels = {
           "kics-engine"             = "true"
           "minio-gateway"           = "true"
           "repostore"               = "true" 
           "sast-engine"             = "true" 
           "sast-engine-extra-large" = "true" 
           "sast-engine-large"       = "true" 
           "sast-engine-medium"      = "true" 
           "sast-engine-xxl"         = "true"
      }
      tags = {
        Name                   = var.deployment_id
        "karpenter.sh/discovery" = var.deployment_id
      }
    }
  }
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

resource "helm_release" "karpenter" {
  depends_on = [module.eks]
  namespace  = "kube-system"

  repository = "oci://public.ecr.aws/karpenter"
  chart      = "karpenter"
  name       = "karpenter"
  version    = "0.35.0"

  set {
    name  = "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.karpenter.iam_role_arn
  }

  set {
    name  = "serviceAccount.name"
    value = "karpenter"
  }

  set {
    name  = "settings.clusterName"
    value = var.deployment_id
  }

  set {
    name  = "settings.clusterEndpoint"
    value = data.aws_eks_cluster.cluster.endpoint
  }

  set {
    name  = "settings.featureGates.spotToSpotConsolidation"
    value = true
  }
}


module "karpenter" {
  source  = "terraform-aws-modules/eks/aws//modules/karpenter"
  version = "20.5.0"

  cluster_name                    = var.deployment_id
  enable_irsa                     = true
  irsa_oidc_provider_arn          = module.eks.oidc_provider_arn
  irsa_namespace_service_accounts = ["kube-system:karpenter"]
  create_iam_role                 = true
  iam_role_name                   = "KarpenterController-${var.deployment_id}"
  iam_role_description            = "I am role for karpenter controller created by karpenter module"
  create_node_iam_role            = false
  node_iam_role_arn               = var.nodegroup_iam_role_arn
  create_access_entry             = false
  iam_policy_name                 = "KarpenterPolicy-${var.deployment_id}"
  iam_policy_description          = "Karpenter controller IAM policy created by karpenter module"

  

  iam_role_use_name_prefix = false
  node_iam_role_additional_policies = {
    AmazonSSMManagedInstanceCore = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
    AmazonEBSCSIDriverPolicy     = "arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"
  }
  enable_spot_termination = true
  queue_name              = "${var.deployment_id}-node-termination-handler"
}

### NodePool
resource "kubectl_manifest" "default_nodepool" {
  yaml_body = <<-YAML
    apiVersion: karpenter.sh/v1beta1
    kind: NodePool
    metadata:
      name: default
    spec:
      template:
        metadata:
          labels:
            repostore: "true"
            sast-engine-xxl: "true"
            kics-engine: "true"
            sast-engine-medium: "true"
            sast-engine: "true"
            minio-gateway: "true"
            sast-engine-extra-large: "true"
            sast-engine-large: "true"
        spec:
          requirements:
            - key: kubernetes.io/arch
              operator: In
              values: ["amd64"]
            - key: kubernetes.io/os
              operator: In
              values: ["linux"]
            - key: karpenter.sh/capacity-type
              operator: In
              values: ["on-demand"]
            - key: karpenter.k8s.aws/instance-category
              operator: In
              values: ["c", "m", "r"]
            - key: karpenter.k8s.aws/instance-generation
              operator: Gt
              values: ["4"]
            - key: "topology.kubernetes.io/zone"
              operator: In
              values: ["us-west-2a", "us-west-2b"]
          nodeClassRef:
            name: default
      limits:
        cpu: 1000
      disruption:
        consolidationPolicy: WhenUnderutilized
  YAML

  depends_on = [
    helm_release.karpenter
  ]
}

### EC2NodeClass
resource "kubectl_manifest" "default_ec2nodeclass" {
  yaml_body = <<-YAML
    apiVersion: karpenter.k8s.aws/v1beta1
    kind: EC2NodeClass
    metadata:
      name: default
    spec:
      amiFamily: AL2 # Amazon Linux 2
      role: ${var.nodegroup_iam_role_name}
      metadataOptions:
        httpEndpoint: enabled
        httpPutResponseHopLimit: 2
        httpTokens: required
      blockDeviceMappings:
      - deviceName: /dev/xvda
        ebs:
          deleteOnTermination: true
          encrypted: true
          volumeSize: 100Gi
          volumeType: gp3
      subnetSelectorTerms:
        - tags:
            karpenter.sh/discovery: ${var.deployment_id}
      securityGroupSelectorTerms:
        - tags:
            karpenter.sh/discovery: ${var.deployment_id}
      tags:
        karpenter.sh/discovery: ${var.deployment_id}
  YAML

  depends_on = [
    helm_release.karpenter
  ]
}
