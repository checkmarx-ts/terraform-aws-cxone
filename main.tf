terraform {
  required_providers {
    aws = {
      source  = "registry.terraform.io/hashicorp/aws"
      version = "~> 6.0.0"
    }
    helm = {
      source  = "registry.terraform.io/hashicorp/helm"
      version = "~> 2.13.0"
    }
    kubernetes = {
      source  = "registry.terraform.io/hashicorp/kubernetes"
      version = "~> 2.30.0"
    }
  }
}