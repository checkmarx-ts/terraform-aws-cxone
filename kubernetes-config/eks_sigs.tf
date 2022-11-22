# AWS IAM Policy for AWS Load Balancer Controller
resource "aws_iam_policy" "aws_load_balancer_controller" {
  name        = "${local.deployment_id}-eks-aws-load-balancer-controller-${var.aws_region}"
  description = "EKS Cluster AWS Load Balancer Controller Policy for ${local.deployment_id}"
  policy      = file("iam/aws-load-balancer-controller.json")
}
# AWS IAM Role for AWS Load Balancer Controller
module "load_balancer_controller_irsa" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "4.13.1"

  role_name        = "load_balancer_controller-${var.deployment_id}"
  role_description = "IRSA role for cluster load balancer controller"

  # setting to false because we don't want to rely on exeternal policies
  attach_load_balancer_controller_policy = false
  oidc_providers = {
    main = {
      provider_arn               = data.terraform_remote_state.infra.outputs.oidc_provider_arn
      namespace_service_accounts = ["kube-system:aws-load-balancer-controller"]
    }
  }
}

# Attache Policy for AWS AIM Role for AWS Load Balancer Controller
resource "aws_iam_role_policy_attachment" "aws-load-balancer-controller-policy-attachment" {
  role       = module.load_balancer_controller_irsa.iam_role_name
  policy_arn = aws_iam_policy.aws_load_balancer_controller.arn
}

## ExternalDNS
# IAM Policy for ExternalDNS
resource "aws_iam_policy" "external-dns" {
  name        = "${local.deployment_id}-eks-external-dns-${var.aws_region}"
  description = "EKS Cluster External DNS Policy for ${local.deployment_id}"
  policy      = file("iam/external-dns.json")
}
# AWS IAM Role for ExternalDNS Controller
module "external_dns_irsa" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "4.13.1"

  role_name        = "external-dns-${var.deployment_id}"
  role_description = "IRSA role for cluster external dns controller"

  # setting to false because we don't want to rely on exeternal policies
  attach_external_dns_policy = false
  oidc_providers = {
    main = {
      provider_arn               = data.terraform_remote_state.infra.outputs.oidc_provider_arn
      namespace_service_accounts = ["kube-system:external-dns"]
    }
  }

}

# Attache Policy for AWS AIM Role for ExternalDNS Controller
resource "aws_iam_role_policy_attachment" "aws-external-dns-policy-attachment" {
  role       = module.external_dns_irsa.iam_role_name
  policy_arn = aws_iam_policy.external-dns.arn
}

# Cluster AutoScaler
# IAM Policy for Cluster AutoScaler
resource "aws_iam_policy" "cluster_autoscaler" {
  name        = "${local.deployment_id}-eks-cluster-autoscaler-${var.aws_region}"
  description = "EKS Cluster Auto Scalers Policy for ${local.deployment_id}"
  policy      = file("iam/cluster-autoscaler.json")
}

# AWS IAM Role for Cluster AutoScaler
module "cluster_autoscaler_irsa" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "4.13.1"

  role_name        = "cluster-autoscaler-${var.deployment_id}"
  role_description = "IRSA role for cluster autoscaler"

  # setting to false because we don't want to rely on exeternal policies
  attach_cluster_autoscaler_policy = false
  cluster_autoscaler_cluster_ids   = [data.terraform_remote_state.infra.outputs.eks_cluster_id]
  oidc_providers = {
    main = {
      provider_arn               = data.terraform_remote_state.infra.outputs.oidc_provider_arn
      namespace_service_accounts = ["kube-system:cluster-autoscaler"]
    }
  }

}

# Attache Policy for AWS AIM Role for Cluster AutoScaler
resource "aws_iam_role_policy_attachment" "aws-cluster-autoscaler-policy-attachment" {
  role       = module.cluster_autoscaler_irsa.iam_role_name
  policy_arn = aws_iam_policy.cluster_autoscaler.arn
}







resource "helm_release" "aws-load-balancer-controller" {
  depends_on = [
    module.load_balancer_controller_irsa
  ]
  name      = "aws-load-balancer-controller"
  chart     = "./helm-charts/aws-load-balancer-controller-1.4.5.tgz"
  version   = "1.4.5"
  namespace = "kube-system"

  set {
    name  = "clusterName"
    value = local.deployment_id
  }
  set {
    name  = "serviceAccount.create"
    value = "false"
  }
  set {
    name  = "serviceAccount.name"
    value = "aws-load-balancer-controller"
  }
  set {
    name  = "region"
    value = var.aws_region
  }
}

# External DNS
resource "helm_release" "external-dns" {
  depends_on = [
    module.external_dns_irsa
  ]
  count     = 1
  name      = "external-dns"
  chart     = "./helm-charts/external-dns-1.11.0.tgz"
  version   = "1.11.0"
  namespace = "kube-system"
  set {
    name  = "txtOwnerId"
    value = var.hosted_zone_id
  }
  set {
    name  = "serviceAccount.create"
    value = false
  }
  set {
    name  = "serviceAccount.name"
    value = "external-dns"
  }
}

resource "helm_release" "cluster-autoscaler" {
  depends_on = [
    module.cluster_autoscaler_irsa
  ]
  count     = 1
  name      = "cluster-autoscaler"
  chart     = "./helm-charts/cluster-autoscaler-9.21.0.tgz"
  version   = "9.21.0"
  namespace = "kube-system"

  set {
    name  = "image.tag"
    value = "v1.23.0"
  }

  set {
    name  = "autoDiscovery.clusterName"
    value = var.deployment_id
  }
  set {
    name  = "awsRegion"
    value = var.aws_region
  }

  set {
    name  = "rbac.create"
    value = "true"
  }
  set {
    name  = "rbac.serviceAccount.create"
    value = "false"
  }
  set {
    name  = "rbac.serviceAccount.name"
    value = "cluster-autoscaler"
  }
}

# AWS IAM Role for AWS ebs csi driver
module "aws_ebs_csi_driver_role" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "4.13.1"

  role_name        = "aws_ebs_csi_driver_role-${var.deployment_id}"
  role_description = "IRSA role for ebs csi driver role"
  oidc_providers = {
    main = {
      provider_arn               = data.terraform_remote_state.infra.outputs.oidc_provider_arn
      namespace_service_accounts = ["kube-system:aws-ebs-csi-driver"]
    }
  }

}

# Attache Policy for AWS AIM Role for AWS ebs csi driver
resource "aws_iam_role_policy_attachment" "aws-ebs-csi-driver-policy-attachment" {
  role       = module.aws_ebs_csi_driver_role.iam_role_name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"
}

# aws ebs csi driver
resource "helm_release" "aws_ebs_csi_driver" {
  depends_on = [
    module.aws_ebs_csi_driver_role
  ]
  count     = 1
  name      = "aws-ebs-csi-driver"
  chart     = "./helm-charts/aws-ebs-csi-driver-2.13.0.tgz"
  version   = "2.13.0"
  namespace = "kube-system"

  set {
    name  = "node.tolerateAllTaints"
    value = "true"
  }
  set {
    name  = "controller.serviceAccount.create"
    value = "false"
  }
  set {
    name  = "controller.serviceAccount.name"
    value = "aws-ebs-csi-driver"
  }
  set {
    name  = "node.serviceAccount.create"
    value = "false"
  }
  set {
    name  = "node.serviceAccount.name"
    value = "aws-ebs-csi-driver"
  }

}

resource "kubernetes_storage_class" "storage_class_gp3" {
  depends_on = [
    helm_release.aws_ebs_csi_driver
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

resource "kubernetes_annotations" "gp2" {
  depends_on = [
    helm_release.aws_ebs_csi_driver
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