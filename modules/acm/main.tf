data "aws_route53_zone" "hosted_zone" {
  name         = var.domain
  private_zone = false
}

module "acm" {
  source  = "terraform-aws-modules/acm/aws"
  version = "5.0.0"

  domain_name = "${var.subdomain}${var.domain}"
  zone_id     = data.aws_route53_zone.hosted_zone.zone_id

  validation_method      = "DNS"
  create_certificate     = true
  create_route53_records = true
  validate_certificate   = true
  wait_for_validation    = true

  tags = {
    Name = var.deployment_id
  }
}