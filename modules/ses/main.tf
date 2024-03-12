data "aws_route53_zone" "hosted_zone" {
  name         = var.domain
  private_zone = false
}

module "ses" {
  source            = "cloudposse/ses/aws"
  version           = "0.24.0"
  zone_id           = data.aws_route53_zone.hosted_zone.zone_id
  domain            = "${var.subdomain}${var.domain}"
  verify_domain     = true
  verify_dkim       = true
  ses_group_enabled = true
  ses_group_name    = "${var.deployment_id}-ses-group"
  ses_user_enabled  = true
  name              = "CxOne-${var.deployment_id}"
  environment       = "dev"
  enabled           = true

  tags = {
    Name = var.deployment_id
  }
}

resource "aws_iam_group_policy" "cxone_ses_group_policy" {
  name  = "cxone_ses_group_policy"
  group = module.ses.ses_group_name

  depends_on = [module.ses]

  policy = jsonencode({
    Version : "2012-10-17"
    Statement : [
      {
        Effect : "Allow",
        Action : [
          "ses:SendEmail",
          "ses:SendRawEmail"
        ],
        Resource : "*"
      }
    ]
  })
}