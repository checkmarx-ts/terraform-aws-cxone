provider "aws" {
  region     = var.aws_region
  profile    = var.aws_profile

  default_tags {
    tags = {
      Terraform    = "true"
      DeploymentID = var.deployment_id
      Owner        = var.owner
      Environment  = var.environment
    }
  }
}

################################################################################
# Kubernetes provider configuration
################################################################################
data "aws_eks_cluster" "cluster" {
  name = var.deployment_id
}

data "aws_eks_cluster_auth" "cluster" {
  name = var.deployment_id
}

provider "kubernetes" {
  host                   = data.aws_eks_cluster.cluster.endpoint
  cluster_ca_certificate = base64decode(data.aws_eks_cluster.cluster.certificate_authority[0].data)
  token                  = data.aws_eks_cluster_auth.cluster.token
}

provider "helm" {
  kubernetes {
    host                   = data.aws_eks_cluster.cluster.endpoint
    cluster_ca_certificate = base64decode(data.aws_eks_cluster.cluster.certificate_authority[0].data)
    token                  = data.aws_eks_cluster_auth.cluster.token
  }
}

data "terraform_remote_state" "infra" {
  backend = "s3"
  config = {
    bucket = var.s3_backend_infra_bucket
    key    = var.s3_backend_infra_remote_config_key
    region = var.s3_backend_infra_bucket_region
  }
}