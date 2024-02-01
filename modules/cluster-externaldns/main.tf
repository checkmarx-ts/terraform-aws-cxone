## EXTERNAL DNS
# AWS IAM POLICY FOR EXTERNAL DNS

data "aws_region" "current" {}

resource "aws_iam_policy" "external-dns-policy" {
  name        = "${var.deployment_id}-external-dns-${data.aws_region.current.name}"
  description = "external dns Policy for ${var.deployment_id}"
  policy      = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "route53:ChangeResourceRecordSets"
            ],
            "Resource": [
                "arn:aws:route53:::hostedzone/*"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "route53:ListHostedZones",
                "route53:ListResourceRecordSets"
            ],
            "Resource": [
                "*"
            ]
        }
    ]
}
EOF
}

# AWS IAM Role FOR ExternalDNS
module "external_dns_irsa" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "5.9.2"

  role_name        = "external-dns-${var.deployment_id}"
  role_description = "IRSA role for cluster external dns controller"

  # setting to false because we don't want to rely on exeternal policies
  attach_external_dns_policy = false
  oidc_providers = {
    main = {
      provider_arn               = var.oidc_provider_arn
      namespace_service_accounts = ["kube-system:external-dns"]
    }
  }
}
# ATTACHE POLICY FOR AWS AIM ROLE FOR EXTERNAL DNS
resource "aws_iam_role_policy_attachment" "external-dns-policy-attachment" {
  role       = module.external_dns_irsa.iam_role_name
  policy_arn = aws_iam_policy.external-dns-policy.arn
}
# HELM ExternalDNS
resource "helm_release" "external-dns" {
  depends_on = [
    module.external_dns_irsa,
    aws_iam_role_policy_attachment.external-dns-policy-attachment
  ]
  count     = 1
  name      = "external-dns"
  chart     = "${path.module}/helm-charts/external-dns-1.11.0.tgz"
  version   = "1.11.0"
  namespace = "kube-system"

  set {
    name  = "serviceAccount.create"
    value = "true"
  }
  set {
    name  = "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.external_dns_irsa.iam_role_arn
  }
  set {
    name  = "serviceAccount.name"
    value = "external-dns"
  }
}