provider "aws" {

  region = "us-west-2"

  default_tags {
    tags = {
      Terraform    = "true"
      DeploymentID = var.deployment_id
      Owner        = var.owner
      Environment  = var.environment
    }
  }
}

provider "kubernetes" {
  host                   = module.eks_cluster.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks_cluster.cluster_certificate_authority_data)
  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    args        = ["eks", "get-token", "--cluster-name", module.eks_cluster.cluster_name]
    command     = "aws"
  }
}

data "aws_eks_cluster_auth" "cluster" {
  depends_on = [module.eks_cluster.cluster_certificate_authority_data]
  name       = var.deployment_id
}

provider "helm" {
  kubernetes {
    host                   = module.eks_cluster.cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks_cluster.cluster_certificate_authority_data)
    token                  = data.aws_eks_cluster_auth.cluster.token
  }
}