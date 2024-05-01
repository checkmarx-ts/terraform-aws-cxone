
#******************************************************************************
#   Base Infrastructure Configuration
#******************************************************************************
# Provide your hosted zone ID that corresponds to the domain used in the fqdn variable.
# The hosted zone is used for validating SSL certificates in ACM and for external DNS.
# If you are not using route 53 for DNS, then route_53_hosted_zone_id is not used, but you must
# also set eks_create_external_dns_irsa = false and provide your SSL certificate ARN in acm_certificate_arn.
route_53_hosted_zone_id = "<enter your hosted zone id e.g. Z0962235AVF65523G11OI"

# FQDN is used for creating DNS and SSL records, and for configuring Traefik host header listeners
fqdn = "example.checkmarx-ps.com"

# Deployment ID is used to name resources. Use something short and can be part of a url (e.g. alphanumberic with hypens)
deployment_id = "cxone-dev"

# Enter the key you want to use for SSH access to EC2 instances launched by EKS. Leave null to access only via SSM.
ec2_key_name = null

# Enter the number of baseline replicas each pod should have in Checkmarx One. Recommend 1 for non-prod environments, 3 or more for production
ms_replica_count = 1

# The ARN to your SSL certificate in ACM. Required when route_53_hosted_zone_id is not provided.
acm_certificate_arn = null

#******************************************************************************
#   VPC Configuration
#******************************************************************************
# Set to your primary VPC CIDR range. Recommend at least a /17 for Checkmarx One.
primary_cidr_block = "10.77.0.0/16"

# The secondary CIDR. Used as described at https://aws.amazon.com/blogs/containers/addressing-ipv4-address-exhaustion-in-amazon-eks-clusters-using-private-nat-gateways/
secondary_cidr_block = "100.64.0.0/18"

# The interface endpoints to create. These have a charge, but are needed if running EKS privately.
interface_vpc_endpoints    = ["ec2", "ec2messages", "ssm", "ssmmessages", "ecr.api", "ecr.dkr", "kms", "logs", "sts", "elasticloadbalancing", "autoscaling"]
create_interface_endpoints = true
create_s3_endpoint         = true

# Firewall only current works for egress filtering, and breaks ingress. Do not enable.
enable_firewall            = false
stateful_default_action    = "aws:drop_established"
include_sca_rules          = true
create_managed_rule_groups = false
managed_rule_groups = ["AbusedLegitMalwareDomainsStrictOrder",
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
additional_suricata_rules = <<EOF
# CxOne must talk to itself when performing token exchange to validate the FQDN (cxiam makes the connection).
#pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"www.example.com"; startswith; nocase; endswith; msg:"matching TLS allowlisted FQDNs"; flow:to_server, established; sid:240331001; rev:1;)
EOF

#******************************************************************************
#   SMTP Configuration
#******************************************************************************
# Enter your SMTP server information here
smtp_host        = "smtp.example.com"
smtp_port        = 587
smtp_user        = "<user name>"
smtp_password    = "???"
smtp_from_sender = "noreply@example.com"

#******************************************************************************
#   S3 Configuration
#******************************************************************************
# Checkmarx One requires an IAM user with S3 access for connectivity to S3 buckets.
# Create the IAM user with S3 access policies, and enter the credentials here.
object_storage_endpoint   = "<enter your s3 region e.g. s3.us-west-2.amazonaws.com>"
object_storage_access_key = "<enter your AWS Access Key for the IAM user that connects to S3 buckets>"
object_storage_secret_key = "<enter your AWS Secret Key for the IAM user that connects to S3 buckets>"

#******************************************************************************
#   Kots & Installation Configuration
#******************************************************************************
# This information is only passed to the install module to generate installation scripts.
kots_admin_email     = "<email address of the CxOne first administrator user>"
kots_release_channel = "beta"
kots_cxone_version   = "3.10.22"
kots_license_file    = "<path to your Checkmarx One license.yml file>"

#******************************************************************************
# terraform-aws-cxone module pass thru variables. all further variables are
# for the top level terraform-aws-cxone module and not this example.
#******************************************************************************
eks_create                               = true
eks_create_cluster_autoscaler_irsa       = true
eks_create_external_dns_irsa             = false # must be false in govcloud
eks_create_load_balancer_controller_irsa = true
eks_create_karpenter                     = false # karpenter not yet working, do not enable
eks_version                              = "1.28"
coredns_version                          = "v1.10.1-eksbuild.7"
kube_proxy_version                       = "v1.28.8-eksbuild.2"
vpc_cni_version                          = "v1.18.0-eksbuild.1"
aws_ebs_csi_driver_version               = "v1.28.0-eksbuild.1"
eks_enable_fargate                       = false # not yet working, do not enable
eks_enable_externalsnat                  = false # leave false, unless working with external nat gateway
eks_enable_custom_networking             = false
eks_private_endpoint_enabled             = true
# When eks_public_endpoint_enabled = false, installation and management commands after Terraform must be run
# from a system with connectivity to the private EKS endpoint, such as a bastion host.
eks_public_endpoint_enabled              = true
eks_cluster_endpoint_public_access_cidrs = ["0.0.0.0/0"] # Use to lock down access to the public endpoint, when the public endpoint is enabled
enable_cluster_creator_admin_permissions = true          # the principal used to execute this terraform will be granted access to EKS
eks_node_additional_security_group_ids   = []            # pass arbitrary additional security groups to EKS nodes
eks_post_bootstrap_user_data             = null
eks_pre_bootstrap_user_data              = null
# Uncomment the eks_administrator_principals to specify additional principal ARNs that should have admin
# access to EKS.
# eks_administrator_principals = [
#   {
#     name          = "YourName1"
#     principal_arn = "arn:aws:iam::1234567890:role/aws-reserved/sso.amazonaws.com/us-east-1/YourRoleName1"
#   },
#   {
#     name          = "YourName2"
#     principal_arn = "arn:aws:iam::1234567890:role/aws-reserved/sso.amazonaws.com/us-east-1/YourName2"
#   }
# ]
# Tags will be applied to EKS nodes created via launch template
launch_template_tags = {
  CostCenter     = "12345"
  "Custom:owner" = "foobar"
}
# EKS node groups, these are required.
eks_node_groups = [{
  name           = "ast-app"
  min_size       = 3
  desired_size   = 3
  max_size       = 9
  instance_types = ["c5.4xlarge"]
  },
  {
    name           = "sast-engine"
    min_size       = 0
    desired_size   = 0
    max_size       = 100
    instance_types = ["m5.2xlarge"]
    labels = {
      "sast-engine" = "true"
    }
    taints = {
      dedicated = {
        key    = "sast-engine"
        value  = "true"
        effect = "NO_SCHEDULE"
      }
    }
  },
  {
    name           = "sast-engine-large"
    min_size       = 0
    desired_size   = 0
    max_size       = 100
    instance_types = ["m5.4xlarge"]
    labels = {
      "sast-engine-large" = "true"
    }
    taints = {
      dedicated = {
        key    = "sast-engine-large"
        value  = "true"
        effect = "NO_SCHEDULE"
      }
    }
  },
  {
    name           = "sast-engine-extra-large"
    min_size       = 0
    desired_size   = 0
    max_size       = 100
    instance_types = ["r5.2xlarge"]
    labels = {
      "sast-engine-extra-large" = "true"
    }
    taints = {
      dedicated = {
        key    = "sast-engine-extra-large"
        value  = "true"
        effect = "NO_SCHEDULE"
      }
    }
  },
  {
    name           = "sast-engine-xxl"
    min_size       = 0
    desired_size   = 0
    max_size       = 100
    instance_types = ["r5.4xlarge"]
    labels = {
      "sast-engine-xxl" = "true"
    }
    taints = {
      dedicated = {
        key    = "sast-engine-xxl"
        value  = "true"
        effect = "NO_SCHEDULE"
      }
    }
  },
  {
    name           = "kics-engine"
    min_size       = 1
    desired_size   = 1
    max_size       = 100
    instance_types = ["c5.2xlarge"]
    labels = {
      "kics-engine" = "true"
    }
    taints = {
      dedicated = {
        key    = "kics-engine"
        value  = "true"
        effect = "NO_SCHEDULE"
      }
    }
  },
  {
    name           = "repostore"
    min_size       = 1
    desired_size   = 1
    max_size       = 100
    instance_types = ["c5.2xlarge"]
    labels = {
      "repostore" = "true"
    }
    taints = {
      dedicated = {
        key    = "repostore"
        value  = "true"
        effect = "NO_SCHEDULE"
      }
    }
  },
  {
    name           = "sca-source-resolver"
    min_size       = 1
    desired_size   = 1
    max_size       = 100
    instance_types = ["m5.2xlarge"]
    labels = {
      "service" = "sca-source-resolver"
    }
    taints = {
      dedicated = {
        key    = "service"
        value  = "sca-source-resolver"
        effect = "NO_SCHEDULE"
      }
    }
  }
]


#******************************************************************************
# RDS Configuration
#******************************************************************************
db_engine_version              = "13.12"
db_allow_major_version_upgrade = true
db_auto_minor_version_upgrade  = true
db_apply_immediately           = true
db_deletion_protection         = false
db_skip_final_snapshot         = true
db_final_snapshot_identifier   = "your-final-snapshot-id"
db_snapshot_identifer          = null
db_instance_class              = "db.serverless" # "db.r6g.large"
db_monitoring_interval         = "10"
# When enabling autoscaling, you may need to edit and save the autoscaling policy (no updates needed)
# to work around the issue described here: https://github.com/terraform-aws-modules/terraform-aws-rds-aurora/issues/432
db_autoscaling_enabled                      = false # Autoscaling not supported by Checkmarx One Single Tenant, yet.
db_autoscaling_min_capacity                 = 1
db_autoscaling_max_capacity                 = 3
db_autoscaling_target_cpu                   = 70
db_autoscaling_scale_out_cooldown           = 300
db_autoscaling_scale_in_cooldown            = 300
db_port                                     = "5432"
db_create_rds_proxy                         = false
db_create                                   = true
db_performance_insights_enabled             = true
db_performance_insights_retention_period    = 7
db_cluster_db_instance_parameter_group_name = "aurora-postgresql13-cluster"
# Set individual instance properties. Reference https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/rds_cluster_instance
db_instances = {
  writer = {}
  # Create replicas for production, but not for non-prod envs
  #replica1 = {
  #  promotion_tier = 0
  #}
}
db_serverlessv2_scaling_configuration = {
  min_capacity = 0.5
  max_capacity = 8
}


#******************************************************************************
# Elasticache Configuration
#******************************************************************************
ec_create                         = true
ec_enable_serverless              = false # Serverless EC is not supported by Checkmarx One, yet.
ec_serverless_max_storage         = 5
ec_serverless_max_ecpu_per_second = 5000
ec_engine_version                 = "6.x"
ec_parameter_group_name           = "default.redis6.x.cluster.on"
ec_automatic_failover_enabled     = true
ec_multi_az_enabled               = true
ec_node_type                      = "cache.t3.medium" # Production: cache.r7g.xlarge, Dev/Test: cache.t4g.medium, Demo: cache.t4g.micro. Note: Not all regions have r7 generation instances.
ec_number_of_shards               = 1                 # Production 3, Dev/Test: 1, Demo: 1
ec_replicas_per_shard             = 2                 # Production 2, Dev/Test: 1, Demo: 0
ec_auto_minor_version_upgrade     = false

#******************************************************************************
# Elasticsearch Configuration
#******************************************************************************
es_create              = true
es_instance_count      = 2
es_instance_type       = "r6g.large.elasticsearch"
es_volume_size         = 50
es_tls_security_policy = "Policy-Min-TLS-1-2-2019-07"
es_username            = "ast"
