provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Terraform    = "true"
      DeploymentID = var.deployment_id
      Owner        = var.owner
      Environment  = var.environment
    }
  }
}