provider "aws" {
  region = var.aws_region
  #profile    = var.aws_profile
  
  default_tags {
    tags = {
      Terraform     = "true"
      DeploymentID  = var.deployment_id
      Owner         = var.owner
      Environment   = var.environment
    }
  }
}