# data-vpc

A VPC module that can be used to read in information from an already existing VPC created outside of Terraform, and also add a secondary VPC CIDR range with subnets for EKS custom networking.

# Example

```
# Create a "data-vpc" to add on pod subnets from a secondary vpc cidr, to an already existing vpc.
module "vpc" {
  source = "../data-vpc"

  deployment_id            = "data-vpc-test"
  vpc_id                   = "vpc-05a4932bcfc6c4262"
  existing_private_subnets = ["subnet-0290a282a40ef8fab", "subnet-05e37414d62fad9c8", "subnet-09f70ae09e46495b8"]
  secondary_vpc_cidr       = "100.74.0.0/17"
}

output "vpc_info" {
  value = module.vpc.*
}
```