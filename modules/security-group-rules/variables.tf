
variable "internal" {
  description = "The internal traffic security group id"
  nullable    = false
}

variable "external" {
  description = "The internal traffic security group id"
  nullable    = false
}

variable "vpc_cidr" {
  description = "The VPC CIDR"
  nullable    = false
}
