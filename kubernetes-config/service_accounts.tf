# SA for Load Balancer Controller
resource "kubernetes_service_account" "aws-load-balancer-controller" {
  depends_on = [
    module.load_balancer_controller_irsa
  ]
  metadata {
    name      = "aws-load-balancer-controller"
    namespace = "kube-system"
    annotations = {
      "eks.amazonaws.com/role-arn" = module.load_balancer_controller_irsa.iam_role_arn
    }
  }
}

# SA for ExternalDNS
resource "kubernetes_service_account" "external-dns" {
  depends_on = [
    module.load_balancer_controller_irsa
  ]
  metadata {
    name      = "external-dns"
    namespace = "kube-system"
    annotations = {
      "eks.amazonaws.com/role-arn" = module.external_dns_irsa.iam_role_arn
    }
  }
}

# SA for Cluster AutoScaler
resource "kubernetes_service_account" "cluster-autoscaler" {
  depends_on = [
    module.load_balancer_controller_irsa
  ]
  metadata {
    name      = "cluster-autoscaler"
    namespace = "kube-system"
    annotations = {
      "eks.amazonaws.com/role-arn" = module.cluster_autoscaler_irsa.iam_role_arn
    }
  }
}

# SA for aws ebs csi driver
resource "kubernetes_service_account" "aws-ebs-csi-driver" {
  depends_on = [
    module.aws_ebs_csi_driver_role
  ]
  metadata {
    name      = "aws-ebs-csi-driver"
    namespace = "kube-system"
    annotations = {
      "eks.amazonaws.com/role-arn" = module.aws_ebs_csi_driver_role.iam_role_arn
    }
  }
}


# SA for Minio
resource "kubernetes_service_account" "minio" {
  depends_on = [
    module.minio_irsa
  ]
  metadata {
    name      = "minio"
    namespace = "ast"
    annotations = {
      "eks.amazonaws.com/role-arn" = module.minio_irsa.iam_role_arn
    }
  }
}