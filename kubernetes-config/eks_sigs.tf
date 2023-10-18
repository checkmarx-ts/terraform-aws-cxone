## AWS LOAD BALANCER CONTROLLER
# AWS IAM POLICY FOR AWS LOAD BALANCER CONTROLLER
resource "aws_iam_policy" "aws_load_balancer_controller" {
  name        = "${local.deployment_id}-eks-aws-load-balancer-controller-${var.aws_region}"
  description = "EKS Cluster AWS Load Balancer Controller Policy for ${local.deployment_id}"
  policy      = file("iam/aws-load-balancer-controller.json")
}
# AWS IAM ROLE FOR AWS LOAD BALANCER CONTROLLER
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
# ATTACHE POLICY FOR AWS AIM ROLE FOR AWS LOAD BALANCER CONTROLLER
resource "aws_iam_role_policy_attachment" "aws-load-balancer-controller-policy-attachment" {
  role       = module.load_balancer_controller_irsa.iam_role_name
  policy_arn = aws_iam_policy.aws_load_balancer_controller.arn
}
# HELM CHART AWS LOAD BALANCER CONTROLLER
resource "helm_release" "aws-load-balancer-controller" {
  depends_on = [
    module.load_balancer_controller_irsa,
    aws_iam_role_policy_attachment.aws-load-balancer-controller-policy-attachment
  ]
  name      = "aws-load-balancer-controller"
  chart     = "./helm-charts/aws-load-balancer-controller-1.4.6.tgz"
  version   = "1.4.6"
  namespace = "kube-system"

  set {
    name  = "clusterName"
    value = local.deployment_id
  }
  set {
    name  = "serviceAccount.create"
    value = "true"
  }
  set {
    name  = "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.load_balancer_controller_irsa.iam_role_arn
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

## CLUSTER AUTO SCALLER
# AWS IAM POLICY FOR CLUSTER AUTOSCALER
resource "aws_iam_policy" "cluster_autoscaler" {
  name        = "${local.deployment_id}-eks-cluster-autoscaler-${var.aws_region}"
  description = "EKS Cluster Auto Scalers Policy for ${local.deployment_id}"
  policy      = file("iam/cluster-autoscaler.json")
}
# AWS IAM ROLE FOR CLUTER AUTOSCALER
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
# ATTACHE POLICY FOR AWS AIM ROLE FOR CLUSTER AUTOSCALER
resource "aws_iam_role_policy_attachment" "aws-cluster-autoscaler-policy-attachment" {
  role       = module.cluster_autoscaler_irsa.iam_role_name
  policy_arn = aws_iam_policy.cluster_autoscaler.arn
}
# HELM CLUSTER AUTOSCALER
resource "helm_release" "cluster-autoscaler" {
  depends_on = [
    module.cluster_autoscaler_irsa,
    aws_iam_role_policy_attachment.aws-cluster-autoscaler-policy-attachment
  ]
  count     = 1
  name      = "cluster-autoscaler"
  chart     = "./helm-charts/cluster-autoscaler-9.21.1.tgz"
  version   = "9.21.1"
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
    name  = "rbac.serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.cluster_autoscaler_irsa.iam_role_arn
  }
  set {
    name  = "rbac.serviceAccount.create"
    value = "true"
  }
  set {
    name  = "rbac.serviceAccount.name"
    value = "cluster-autoscaler"
  }
}

## AWS EBS CSI DRIVER
# AWS IAM POLICY FOR AWS EBS CSI DRIVER
resource "aws_iam_policy" "aws-ebs-csi-driver-policy" {
  name        = "${local.deployment_id}-aws-ebs-csi-driver-${var.aws_region}"
  description = "AWS ebs csi driver Policy for ${local.deployment_id}"
  policy      = file("iam/aws-ebs-csi-driver.json")
}
# AWS EBS CSI DRIVER ROLE  
module "aws_ebs_csi_driver_role" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "5.9.2"

  role_name        = "aws_ebs_csi_driver_role-${var.deployment_id}"
  role_description = "IRSA role for ebs csi driver role"

  # setting to false because we don't want to rely on exeternal policies
  attach_ebs_csi_policy = false
  oidc_providers = {
    main = {
      provider_arn               = data.terraform_remote_state.infra.outputs.oidc_provider_arn
      namespace_service_accounts = ["kube-system:aws-ebs-csi-driver-controller", "kube-system:aws-ebs-csi-driver-node"]
    }
  }
}
# ATTACHE POLICY FOR AWS AIM ROLE FOR AWS EBS CSI DRIVER
resource "aws_iam_role_policy_attachment" "aws-ebs-csi-driver-policy-attachment" {
  role       = module.aws_ebs_csi_driver_role.iam_role_name
  policy_arn = aws_iam_policy.aws-ebs-csi-driver-policy.arn
}
# HELM CHART EBS CSI DRIVER
resource "helm_release" "aws_ebs_csi_driver" {
  depends_on = [
    module.aws_ebs_csi_driver_role,
    aws_iam_role_policy_attachment.aws-ebs-csi-driver-policy-attachment
  ]
  count     = 1
  name      = "aws-ebs-csi-driver"
  chart     = "./helm-charts/aws-ebs-csi-driver-2.14.1.tgz"
  version   = "2.14.1"
  namespace = "kube-system"

  set {
    name  = "node.tolerateAllTaints"
    value = "true"
  }
  set {
    name  = "controller.serviceAccount.create"
    value = "true"
  }
  set {
    name  = "controller.serviceAccount.name"
    value = "aws-ebs-csi-driver-controller"
  }
  set {
    name  = "controller.serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.aws_ebs_csi_driver_role.iam_role_arn
  }
  set {
    name  = "node.serviceAccount.create"
    value = "true"
  }
  set {
    name  = "node.serviceAccount.name"
    value = "aws-ebs-csi-driver-node"
  }
  set {
    name  = "node.serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.aws_ebs_csi_driver_role.iam_role_arn
  }
  set {
    name  = "enableVolumeSnapshot"
    value = "true"
  }
}

## AWS EFS CSI DRIVER
# AWS IAM POLICY FOR AWS EFS CSI DRIVER
resource "aws_iam_policy" "aws-efs-csi-driver-policy" {
  name        = "${local.deployment_id}-aws-efs-csi-driver-${var.aws_region}"
  description = "AWS efs csi driver Policy for ${local.deployment_id}"
  policy      = file("iam/aws-efs-csi-driver.json")
}
# AWS EFS CSI DRIVER ROLE
module "aws_efs_csi_driver_role" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "5.9.2"

  role_name        = "aws_efs_csi_driver_role-${var.deployment_id}"
  role_description = "IRSA role for efs csi driver role"

  # setting to false because we don't want to rely on exeternal policies
  attach_efs_csi_policy = false
  oidc_providers = {
    main = {
      provider_arn               = data.terraform_remote_state.infra.outputs.oidc_provider_arn
      namespace_service_accounts = ["kube-system:efs-csi-controller-sa", "kube-system:efs-csi-node-sa"]
    }
  }
}
# ATTACHE POLICY FOR AWS AIM ROLE FOR AWS EFS CSI DRIVER
resource "aws_iam_role_policy_attachment" "aws-efs-csi-driver-policy-attachment" {
  role       = module.aws_efs_csi_driver_role.iam_role_name
  policy_arn = aws_iam_policy.aws-efs-csi-driver-policy.arn
}
# # HELM CHART EFS CSI DRIVER
resource "helm_release" "aws_efs_csi_driver" {
  depends_on = [
    module.aws_ebs_csi_driver_role,
    aws_iam_role_policy_attachment.aws-efs-csi-driver-policy-attachment
  ]
  count     = 1
  name      = "aws-efs-csi-driver"
  chart     = "./helm-charts/aws-efs-csi-driver-2.3.3.tgz"
  version   = "2.3.3"
  namespace = "kube-system"

  set {
    name  = "controller.serviceAccount.create"
    value = "true"
  }
  set {
    name  = "controller.serviceAccount.name"
    value = "efs-csi-controller-sa"
  }
  set {
    name  = "controller.serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.aws_efs_csi_driver_role.iam_role_arn
  }
  set {
    name  = "node.serviceAccount.create"
    value = "true"
  }
  set {
    name  = "node.serviceAccount.name"
    value = "efs-csi-node-sa"
  }
  set {
    name  = "node.serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.aws_efs_csi_driver_role.iam_role_arn
  }
  set {
    name  = "node.tolerateAllTaints"
    value = "true"
  }
  set {
    name  = "serviceAccount.snapshot.create"
    value = "true"
  }
  set {
    name  = "serviceAccount.snapshot.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.aws_ebs_csi_driver_role.iam_role_arn
  }
  set {
    name  = "serviceAccount.snapshot.name"
    value = "aws-ebs-csi-driver"
  }
  set {
    name  = "enableVolumeScheduling"
    value = "true"
  }
  set {
    name  = "enableVolumeResizing"
    value = "true"
  }
  set {
    name  = "enableVolumeSnapshot"
    value = "true"
  }
}

## STORAGE CLASS
# AWS STORAGE CLASS GP3
resource "kubernetes_storage_class" "storage_class_gp3" {
  depends_on = [
    helm_release.aws_ebs_csi_driver,
    helm_release.aws_efs_csi_driver
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
    helm_release.aws_ebs_csi_driver,
    helm_release.aws_efs_csi_driver
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

## EXTERNAL DNS
# AWS IAM POLICY FOR EXTERNAL DNS
resource "aws_iam_policy" "external-dns-policy" {
  name        = "${local.deployment_id}-external-dns-${var.aws_region}"
  description = "external dns Policy for ${local.deployment_id}"
  policy      = file("iam/external-dns.json")
}
# AWS IAM Role FOR ExternalDNS
module "external_dns_irsa" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "5.9.2"

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
# ATTACHE POLICY FOR AWS AIM ROLE FOR EXTERNAL DNS
resource "aws_iam_role_policy_attachment" "external-dns-policy-attachment" {
  role       = module.external_dns_irsa.iam_role_name
  policy_arn = aws_iam_policy.external-dns-policy.arn
}
# HELM ExternalDNS
resource "helm_release" "external-dns" {
  depends_on = [
    module.external_dns_irsa,
    aws_iam_role_policy_attachment.external-dns-policy-attachment
  ]
  count     = 1
  name      = "external-dns"
  chart     = "./helm-charts/external-dns-1.11.0.tgz"
  version   = "1.11.0"
  namespace = "kube-system"

  set {
    name  = "serviceAccount.create"
    value = "true"
  }
  set {
    name  = "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.external_dns_irsa.iam_role_arn
  }
  set {
    name  = "serviceAccount.name"
    value = "external-dns"
  }
}