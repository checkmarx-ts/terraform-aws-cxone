
data "aws_iam_policy_document" "aws_cluster_access" {
  count = var.create_cluster_access_role ? 1 : 0
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = [var.administrator_iam_role_arn]
    }
  }
}

resource "aws_iam_role" "cluster_access_role" {
  count              = var.create_cluster_access_role ? 1 : 0
  name               = "${var.deployment_id}-cluster-access"
  assume_role_policy = data.aws_iam_policy_document.aws_cluster_access[0].json
  description        = "Role used for admin EKS cluster access for the deployment with id ${var.deployment_id}."
}


module "ebs_csi_irsa" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "5.48.0"
  count   = var.create_ebs_csi_irsa ? 1 : 0

  role_name             = "ebs-csi-${var.deployment_id}"
  role_description      = "IRSA role for EBS CSI Driver"
  attach_ebs_csi_policy = true
  ebs_csi_kms_cmk_ids   = [var.eks_kms_key_arn]
  oidc_providers = {
    main = {
      provider_arn               = var.oidc_provider_arn
      namespace_service_accounts = ["kube-system:ebs-csi-controller-sa"]
    }
  }
}


module "cluster_autoscaler_irsa" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "5.48.0"
  count   = var.create_cluster_autoscaler_irsa ? 1 : 0

  role_name                        = "cluster-autoscaler-${var.deployment_id}"
  role_description                 = "IRSA role for cluster autoscaler"
  attach_cluster_autoscaler_policy = true

  cluster_autoscaler_cluster_names = [var.deployment_id]
  oidc_providers = {
    main = {
      provider_arn               = var.oidc_provider_arn
      namespace_service_accounts = ["kube-system:cluster-autoscaler"]
    }
  }
}


module "external_dns_irsa" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "5.48.0"
  count   = var.create_external_dns_irsa ? 1 : 0

  role_name        = "external-dns-${var.deployment_id}"
  role_description = "IRSA role for cluster external dns controller"
  #external_dns_hosted_zone_arns = var.external_dns_hosted_zone_arns
  # setting to false because we don't want to rely on exeternal policies
  attach_external_dns_policy = true
  oidc_providers = {
    main = {
      provider_arn               = var.oidc_provider_arn
      namespace_service_accounts = ["kube-system:external-dns"]
    }
  }
}


module "load_balancer_controller_irsa" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "5.48.0"
  count   = var.create_load_balancer_controller_irsa ? 1 : 0

  role_name                              = "load_balancer_controller-${var.deployment_id}"
  role_description                       = "IRSA role for cluster load balancer controller"
  attach_load_balancer_controller_policy = true
  oidc_providers = {
    main = {
      provider_arn               = var.oidc_provider_arn
      namespace_service_accounts = ["kube-system:aws-load-balancer-controller"]
    }
  }
}