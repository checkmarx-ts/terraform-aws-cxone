
variable "primary_cidr_block" {
  description = "The primary VPC CIDR block for the VPC. Must be at least a /19."
  type        = string
  nullable    = false
}

variable "secondary_cidr_block" {
  description = "The secondary VPC CIDR block for the EKS Pod [Custom Networking](https://aws.github.io/aws-eks-best-practices/networking/custom-networking/) configuration. Must be at least a /18."
  type        = string
  default     = "100.64.0.0/18"
  nullable    = false
}

variable "interface_vpc_endpoints" {
  type        = list(string)
  description = "A list of AWS services to create [VPC Private Endpoints](https://docs.aws.amazon.com/vpc/latest/privatelink/privatelink-access-aws-services.html) for. These endpoints are used for communication direct to AWS services without requiring connectivity and are useful for private EKS clusters."
  default     = ["ec2", "ec2messages", "ssm", "ssmmessages", "ecr.api", "ecr.dkr", "kms", "logs", "sts", "elasticloadbalancing", "autoscaling"]
}

variable "create_interface_endpoints" {
  type        = bool
  description = "Enables creation of the [interface endpoints](https://docs.aws.amazon.com/vpc/latest/privatelink/privatelink-access-aws-services.html) specified in `interface_vpc_endpoints`"
  default     = true
}

variable "create_s3_endpoint" {
  type        = bool
  description = "Enables creation of the [s3 gateway VPC endpoint](https://docs.aws.amazon.com/vpc/latest/privatelink/vpc-endpoints-s3.html)"
  default     = true
}

variable "enable_firewall" {
  description = "Enables the use of the [AWS Network Firewall](https://docs.aws.amazon.com/network-firewall/latest/developerguide/what-is-aws-network-firewall.html) to protect the private and pod subnets"
  type        = bool
  default     = true
}

variable "stateful_default_action" {
  description = "The [default action](https://docs.aws.amazon.com/network-firewall/latest/developerguide/suricata-rule-evaluation-order.html#suricata-strict-rule-evaluation-order) for the AWS Network Firewall stateful rule group. Choose `aws:drop_established` or `aws:alert_established`"
  type        = string
  default     = "aws:drop_established"
}

variable "suricata_rules" {
  description = "The [suricata rules](https://docs.aws.amazon.com/network-firewall/latest/developerguide/suricata-examples.html) to use for the AWS Network Firewall. When provided, this variable completely overrides the embedded rules. Use this to bring your own rules. If you only need to provide some additional rules in addition to the bundled rules, then use `additional_suricata_rules` instead of `suricata_rules`."
  type        = string
  default     = null
}

variable "include_sca_rules" {
  description = "Enables inclusion of AWS Network Firewall rules used in SCA scanning. These rules may be overly permissive when not using SCA, so they are optional. These rules allow connectivity to various public package manager repositories like [Maven Central](https://mvnrepository.com/repos/central) and [npm](https://docs.npmjs.com/)."
  type        = bool
  default     = true
}

variable "additional_suricata_rules" {
  description = "Additional [suricata rules](https://docs.aws.amazon.com/network-firewall/latest/developerguide/suricata-examples.html) rules to use in the network firewall. When provided these rules will be appended to the default rules prior to the default drop rule."
  type        = string
  default     = ""
}

variable "create_managed_rule_groups" {
  type        = bool
  description = "Enables creation of the AWS Network Firewall [managed rule groups](https://docs.aws.amazon.com/network-firewall/latest/developerguide/aws-managed-rule-groups-list.html) provided in `managed_rule_groups`"
  default     = true
}

variable "managed_rule_groups" {
  description = "The AWS Network Firewall [managed rule groups](https://docs.aws.amazon.com/network-firewall/latest/developerguide/aws-managed-rule-groups-list.html) to include in the firewall policy. Must be strict order groups. "
  type        = list(string)
  # ThreatSignaturesFUPStrictOrder and ThreatSignaturesPhishingStrictOrder are not included by default, as you can only have 20 stateful rule groups per FW policy.
  default = ["AbusedLegitMalwareDomainsStrictOrder",
    "MalwareDomainsStrictOrder",
    "AbusedLegitBotNetCommandAndControlDomainsStrictOrder",
    "BotNetCommandAndControlDomainsStrictOrder",
    "ThreatSignaturesBotnetStrictOrder",
    "ThreatSignaturesBotnetWebStrictOrder",
    "ThreatSignaturesBotnetWindowsStrictOrder",
    "ThreatSignaturesIOCStrictOrder",
    "ThreatSignaturesDoSStrictOrder",
    "ThreatSignaturesEmergingEventsStrictOrder",
    "ThreatSignaturesExploitsStrictOrder",
    "ThreatSignaturesMalwareStrictOrder",
    "ThreatSignaturesMalwareCoinminingStrictOrder",
    "ThreatSignaturesMalwareMobileStrictOrder",
    "ThreatSignaturesMalwareWebStrictOrder",
    "ThreatSignaturesScannersStrictOrder",
    "ThreatSignaturesSuspectStrictOrder",
    "ThreatSignaturesWebAttacksStrictOrder"
  ]
}
