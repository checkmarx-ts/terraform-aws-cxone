variable "region" {
  type        = string
  description = "The AWS region e.g. us-east-1, us-west-2, etc."
}

variable "admin_email" {
  type        = string
  description = "The email of the first admin user."
}

variable "admin_password" {
  type        = string
  description = "The password for the first admin user. Must be > 14 characters."
}

variable "fqdn" {
  type        = string
  description = "The fully qualified domain name that will be used for the Checkmarx One deployment"
}

variable "deployment_id" {
  description = "The id of the deployment. Will be used to name resources like EKS cluster, etc."
  type        = string
  nullable    = false
  validation {
    condition     = (length(var.deployment_id) >= 3)
    error_message = "The deployment_id must be greater than 3 characters."
  }
}

variable "cxone_namespace" {
  description = "The kubernetes namespace in which to deploy the CxOne application."
  type        = string
  default     = "ast"
}

variable "vpc_id" {
  description = "The VPC Id Checkmarx One is deployed into."
  type        = string
}

variable "bucket_suffix" {
  description = "The id of the deployment. Will be used to name resources like EKS cluster, etc."
  type        = string
  nullable    = false
  validation {
    condition     = (length(var.bucket_suffix) > 3)
    error_message = "The deployment_id must be greater than 3 characters."
  }
}

variable "cxone_version" {
  type        = string
  description = "The version of CxOne to install"
}

variable "release_channel" {
  type        = string
  description = "The release channel to deploy from"
}

variable "license_file" {
  type        = string
  description = "The path to the license file to use"
}

variable "kots_admin_password" {
  type        = string
  description = "The Kots password to use"
}

variable "ms_replica_count" {
  type        = number
  description = "The microservices replica count (e.g. a minimum)"
  default     = 3
}

variable "cluster_autoscaler_iam_role_arn" {
  type     = string
  nullable = true
}

variable "external_dns_iam_role_arn" {
  type     = string
  nullable = true
}

variable "load_balancer_controller_iam_role_arn" {
  type     = string
  nullable = true
}

variable "karpenter_iam_role_arn" {
  type     = string
  nullable = true
}

variable "cluster_endpoint" {
  type     = string
  nullable = true
}

variable "nodegroup_iam_role_name" {
  type     = string
  nullable = true
}

variable "availability_zones" {
  type     = list(string)
  nullable = false
}

#******************************************************************************
#   S3 Access Configuration
#******************************************************************************
variable "object_storage_endpoint" {
  type        = string
  description = "The S3 endpoint to use to access buckets"
}

variable "object_storage_access_key" {
  type        = string
  description = "The S3 access key to use to access buckets"
}
variable "object_storage_secret_key" {
  type        = string
  description = "The S3 secret key to use to access buckets"
}

variable "postgres_host" {
  type        = string
  description = "The endpoint for the main RDS server."
}

variable "postgres_read_host" {
  type        = string
  description = "The endpoint for the main RDS server readonly endpoint."
  default     = null
}

variable "postgres_user" {
  type        = string
  description = "The user name for the main RDS server."
  default     = "ast"
}

variable "postgres_password" {
  type        = string
  description = "The user name for the main RDS server."
  default     = "ast"
}

variable "postgres_database_name" {
  type        = string
  description = "The name of the main database."
  default     = "ast"
}

variable "analytics_postgres_host" {
  type        = string
  description = "The endpoint for the analytics RDS server."
}

variable "analytics_postgres_read_host" {
  type        = string
  description = "The endpoint for the analytics RDS server readonly endpoint."
  default     = null
}

variable "analytics_postgres_database_name" {
  type        = string
  description = "The name of the analytics database."
}

variable "analytics_postgres_user" {
  type        = string
  description = "The user name for the analytics RDS server."
  default     = "ast"
}

variable "analytics_postgres_password" {
  type        = string
  description = "The user name for the analytics RDS server."
}

variable "redis_address" {
  type        = string
  description = "The redis endpoint."
}

variable "redis_port" {
  type        = string
  default     = "6379"
  description = "The redis port"
}


#******************************************************************************
#   Elasticsearch Configuration
#******************************************************************************

variable "elasticsearch_host" {
  type    = string
  default = "The elasticsearc host address."
}

variable "elasticsearch_password" {
  type    = string
  default = "The elasticsearch password."
}

#******************************************************************************
#   SMTP Configuration
#******************************************************************************
variable "smtp_host" {
  description = "The hostname of the SMTP server."
  type        = string
}

variable "smtp_port" {
  description = "The port of the SMTP server."
  type        = number
}

variable "smtp_user" {
  description = "The smtp user name."
  type        = string
}

variable "smtp_password" {
  description = "The smtp password."
  type        = string
}

variable "smtp_from_sender" {
  description = "The address to use in the from field when sending emails."
  type        = string
}

#******************************************************************************
#   Keys
#******************************************************************************
variable "core_configuration_encryption_key" {
  description = "The core configuraiton key for the system. Autogenerated if left unspecified."
  type        = string
  default     = null
}

variable "sca_client_secret" {
  description = "The SCA client secret for the system. Autogenerated if left unspecified."
  type        = string
  default     = null
}

variable "integration_encryption_key" {
  description = "The integrations encryption key for the system. Autogenerated if left unspecified."
  type        = string
  default     = null
}

variable "integrations_repos_manager_azure_tenant_key" {
  description = "The integrations Azure tenant key. Autogenerated if left unspecified."
  type        = string
  default     = null
}

variable "integrations_repos_manager_bitbucket_tenant_key" {
  description = "The integrations bitbucket tenant key. Autogenerated if left unspecified."
  type        = string
  default     = null
}

variable "integrations_repos_manager_github_tenant_key" {
  description = "The integrations github tenant key. Autogenerated if left unspecified."
  type        = string
  default     = null
}

variable "integrations_repos_manager_gitlab_tenant_key" {
  description = "The integrations gitlab tenant key. Autogenerated if left unspecified."
  type        = string
  default     = null
}

variable "integrations_webhook_encryption_key" {
  description = "The integrations webhook encryption key. Autogenerated if left unspecified."
  type        = string
  default     = null
}

variable "kms_key_arn" {
  description = "The ARN to the KMS key of the system."
  type        = string
}

#******************************************************************************
#  CxOne Component Configuration
#******************************************************************************
variable "sca_prod_environment" {
  description = "The SCA API endpoint to configure. Options are https://api-sca.checkmarx.net and https://eu.api-sca.checkmarx.net."
  type        = string
  default     = "https://api-sca.checkmarx.net"
}

#******************************************************************************
#  Loadbalancer Configuration
#******************************************************************************

variable "acm_certificate_arn" {
  type        = string
  description = "The ARN for the ACM certificate to use to configure SSL with."
}

variable "network_load_balancer_scheme" {
  description = "The load balancer scheme."
  type        = string
  default     = "internet-facing"
  validation {
    condition     = contains(["internet-facing", "internal"], var.network_load_balancer_scheme)
    error_message = "Valid values for variable network_load_balancer_scheme are internet-facing or internal"
  }
}

#******************************************************************************
#  Internal Certificate Authorities
#******************************************************************************

variable "internal_ca_cert" {
  description = "The base64 encoded pem file containing certificates to add to CxOne components' trust stores"
  type        = string
  default     = ""
}

#******************************************************************************
#  Airgap Support
#******************************************************************************

variable "airgap_bundle_path" {
  description = "The file path to the airgap bundle."
  type        = string
  default     = ""
}

variable "kots_registry" {
  description = "The registry address to use for airgap installation."
  type        = string
  default     = ""
}

variable "kots_registry_username" {
  description = "The registry username to use for airgap installation."
  type        = string
  default     = ""
}

variable "kots_registry_password" {
  description = "The registry password to use for airgap installation."
  type        = string
  default     = ""
}

variable "kots_advanced_config" {
  description = "The kots advanced config section."
  type        = string
  default     = <<-EOF
camunda-platform:
  zeebeGateway:
    resources:
      requests:
        cpu: "1000m"
      limits:
        cpu: "1000m"
EOF
}

variable "redis_tls_skipverify" {
  description = "Skip verification of REDIS TLS connections."
  type        = bool
  default     = true
}

variable "redis_tls_enabled" {
  description = "Enables REDIS TLS connections."
  type        = bool
  default     = false
}

variable "redis_auth_token" {
  description = "The REDIS Auth token."
  type        = string
  default     = ""
}

#******************************************************************************
#   Cluster Proxy Configuration
#******************************************************************************

variable "cluster_proxy_enabled" {
  description = "Controls deployment of a proxy instance for the eks cluster to the VPC."
  type        = bool
  default     = false
}

variable "cluster_proxy_ami" {
  description = "The ami to use for the cluster proxy instance."
  type        = string
  default     = "ami-075686beab831bb7f"
}

variable "cluster_proxy_instance_type" {
  description = "The instance type for the cluster proxy."
  type        = string
  default     = "t3.large"
}

variable "cluster_proxy_user_data" {
  description = "User data for the cluster proxy. Default behavior is to install squid proxy."
  type        = string
  default     = null
}

variable "cluster_proxy_ip" {
  description = "The ip address for the cluster proxy instance."
  type        = string
  default     = "10.x.x.x"
}

variable "cluster_proxy_port" {
  description = "The port used for the cluster proxy instance."
  type        = string
  default     = "3128"
}