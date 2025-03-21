

# Module Documentation
<!-- BEGIN_TF_DOCS -->
## Requirements

No requirements.

## Providers

| Name | Version |
|------|---------|
| <a name="provider_local"></a> [local](#provider\_local) | n/a |
| <a name="provider_random"></a> [random](#provider\_random) | n/a |

## Modules

No modules.

## Resources

| Name | Type |
|------|------|
| [local_file.ENIConfig](https://registry.terraform.io/providers/hashicorp/local/latest/docs/resources/file) | resource |
| [local_file.destroy_load_balancer](https://registry.terraform.io/providers/hashicorp/local/latest/docs/resources/file) | resource |
| [local_file.karpenter_configuration](https://registry.terraform.io/providers/hashicorp/local/latest/docs/resources/file) | resource |
| [local_file.kots_config](https://registry.terraform.io/providers/hashicorp/local/latest/docs/resources/file) | resource |
| [local_file.makefile](https://registry.terraform.io/providers/hashicorp/local/latest/docs/resources/file) | resource |
| [local_file.storage_class](https://registry.terraform.io/providers/hashicorp/local/latest/docs/resources/file) | resource |
| [random_password.core_configuration_encryption_key](https://registry.terraform.io/providers/hashicorp/random/latest/docs/resources/password) | resource |
| [random_password.dast_scan_manager_encryption_hex_key](https://registry.terraform.io/providers/hashicorp/random/latest/docs/resources/password) | resource |
| [random_password.integration_encryption_key](https://registry.terraform.io/providers/hashicorp/random/latest/docs/resources/password) | resource |
| [random_password.integrations_repos_manager_azure_tenant_key](https://registry.terraform.io/providers/hashicorp/random/latest/docs/resources/password) | resource |
| [random_password.integrations_repos_manager_bitbucket_tenant_key](https://registry.terraform.io/providers/hashicorp/random/latest/docs/resources/password) | resource |
| [random_password.integrations_repos_manager_github_tenant_key](https://registry.terraform.io/providers/hashicorp/random/latest/docs/resources/password) | resource |
| [random_password.integrations_repos_manager_gitlab_tenant_key](https://registry.terraform.io/providers/hashicorp/random/latest/docs/resources/password) | resource |
| [random_password.integrations_webhook_encryption_key](https://registry.terraform.io/providers/hashicorp/random/latest/docs/resources/password) | resource |
| [random_password.sca_client_secret](https://registry.terraform.io/providers/hashicorp/random/latest/docs/resources/password) | resource |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_acm_certificate_arn"></a> [acm\_certificate\_arn](#input\_acm\_certificate\_arn) | The ARN for the ACM certificate to use to configure SSL with. | `string` | n/a | yes |
| <a name="input_admin_email"></a> [admin\_email](#input\_admin\_email) | The email of the first admin user. | `string` | n/a | yes |
| <a name="input_admin_password"></a> [admin\_password](#input\_admin\_password) | The password for the first admin user. Must be > 14 characters. | `string` | n/a | yes |
| <a name="input_airgap_bundle_path"></a> [airgap\_bundle\_path](#input\_airgap\_bundle\_path) | The file path to the airgap bundle. | `string` | `""` | no |
| <a name="input_analytics_postgres_database_name"></a> [analytics\_postgres\_database\_name](#input\_analytics\_postgres\_database\_name) | The name of the analytics database. | `string` | n/a | yes |
| <a name="input_analytics_postgres_host"></a> [analytics\_postgres\_host](#input\_analytics\_postgres\_host) | The endpoint for the analytics RDS server. | `string` | n/a | yes |
| <a name="input_analytics_postgres_password"></a> [analytics\_postgres\_password](#input\_analytics\_postgres\_password) | The user name for the analytics RDS server. | `string` | n/a | yes |
| <a name="input_analytics_postgres_read_host"></a> [analytics\_postgres\_read\_host](#input\_analytics\_postgres\_read\_host) | The endpoint for the analytics RDS server readonly endpoint. | `string` | `null` | no |
| <a name="input_analytics_postgres_user"></a> [analytics\_postgres\_user](#input\_analytics\_postgres\_user) | The user name for the analytics RDS server. | `string` | `"ast"` | no |
| <a name="input_availability_zones"></a> [availability\_zones](#input\_availability\_zones) | n/a | `list(string)` | n/a | yes |
| <a name="input_bucket_suffix"></a> [bucket\_suffix](#input\_bucket\_suffix) | The id of the deployment. Will be used to name resources like EKS cluster, etc. | `string` | n/a | yes |
| <a name="input_cluster_autoscaler_iam_role_arn"></a> [cluster\_autoscaler\_iam\_role\_arn](#input\_cluster\_autoscaler\_iam\_role\_arn) | n/a | `string` | n/a | yes |
| <a name="input_cluster_endpoint"></a> [cluster\_endpoint](#input\_cluster\_endpoint) | n/a | `string` | n/a | yes |
| <a name="input_core_configuration_encryption_key"></a> [core\_configuration\_encryption\_key](#input\_core\_configuration\_encryption\_key) | The core configuraiton key for the system. Autogenerated if left unspecified. | `string` | `null` | no |
| <a name="input_cxone_namespace"></a> [cxone\_namespace](#input\_cxone\_namespace) | The kubernetes namespace in which to deploy the CxOne application. | `string` | `"ast"` | no |
| <a name="input_cxone_version"></a> [cxone\_version](#input\_cxone\_version) | The version of CxOne to install | `string` | n/a | yes |
| <a name="input_dast_scan_manager_encryption_hex_key"></a> [dast\_scan\_manager\_encryption\_hex\_key](#input\_dast\_scan\_manager\_encryption\_hex\_key) | The dast scan configuraiton key for the system. Autogenerated if left unspecified. | `string` | `null` | no |
| <a name="input_deployment_id"></a> [deployment\_id](#input\_deployment\_id) | The id of the deployment. Will be used to name resources like EKS cluster, etc. | `string` | n/a | yes |
| <a name="input_elasticsearch_host"></a> [elasticsearch\_host](#input\_elasticsearch\_host) | n/a | `string` | `"The elasticsearc host address."` | no |
| <a name="input_elasticsearch_password"></a> [elasticsearch\_password](#input\_elasticsearch\_password) | n/a | `string` | `"The elasticsearch password."` | no |
| <a name="input_external_dns_iam_role_arn"></a> [external\_dns\_iam\_role\_arn](#input\_external\_dns\_iam\_role\_arn) | n/a | `string` | n/a | yes |
| <a name="input_fqdn"></a> [fqdn](#input\_fqdn) | The fully qualified domain name that will be used for the Checkmarx One deployment | `string` | n/a | yes |
| <a name="input_integration_encryption_key"></a> [integration\_encryption\_key](#input\_integration\_encryption\_key) | The integrations encryption key for the system. Autogenerated if left unspecified. | `string` | `null` | no |
| <a name="input_integrations_repos_manager_azure_tenant_key"></a> [integrations\_repos\_manager\_azure\_tenant\_key](#input\_integrations\_repos\_manager\_azure\_tenant\_key) | The integrations Azure tenant key. Autogenerated if left unspecified. | `string` | `null` | no |
| <a name="input_integrations_repos_manager_bitbucket_tenant_key"></a> [integrations\_repos\_manager\_bitbucket\_tenant\_key](#input\_integrations\_repos\_manager\_bitbucket\_tenant\_key) | The integrations bitbucket tenant key. Autogenerated if left unspecified. | `string` | `null` | no |
| <a name="input_integrations_repos_manager_github_tenant_key"></a> [integrations\_repos\_manager\_github\_tenant\_key](#input\_integrations\_repos\_manager\_github\_tenant\_key) | The integrations github tenant key. Autogenerated if left unspecified. | `string` | `null` | no |
| <a name="input_integrations_repos_manager_gitlab_tenant_key"></a> [integrations\_repos\_manager\_gitlab\_tenant\_key](#input\_integrations\_repos\_manager\_gitlab\_tenant\_key) | The integrations gitlab tenant key. Autogenerated if left unspecified. | `string` | `null` | no |
| <a name="input_integrations_webhook_encryption_key"></a> [integrations\_webhook\_encryption\_key](#input\_integrations\_webhook\_encryption\_key) | The integrations webhook encryption key. Autogenerated if left unspecified. | `string` | `null` | no |
| <a name="input_internal_ca_cert"></a> [internal\_ca\_cert](#input\_internal\_ca\_cert) | The base64 encoded pem file containing certificates to add to CxOne components' trust stores | `string` | `""` | no |
| <a name="input_karpenter_iam_role_arn"></a> [karpenter\_iam\_role\_arn](#input\_karpenter\_iam\_role\_arn) | n/a | `string` | n/a | yes |
| <a name="input_kms_key_arn"></a> [kms\_key\_arn](#input\_kms\_key\_arn) | The ARN to the KMS key of the system. | `string` | n/a | yes |
| <a name="input_kots_admin_password"></a> [kots\_admin\_password](#input\_kots\_admin\_password) | The Kots password to use | `string` | n/a | yes |
| <a name="input_kots_advanced_config"></a> [kots\_advanced\_config](#input\_kots\_advanced\_config) | The kots advanced config section. | `string` | `"camunda-platform:\n  zeebeGateway:\n    resources:\n      requests:\n        cpu: \"1000m\"\n      limits:\n        cpu: \"1000m\"\n"` | no |
| <a name="input_kots_registry"></a> [kots\_registry](#input\_kots\_registry) | The registry address to use for airgap installation. | `string` | `""` | no |
| <a name="input_kots_registry_password"></a> [kots\_registry\_password](#input\_kots\_registry\_password) | The registry password to use for airgap installation. | `string` | `""` | no |
| <a name="input_kots_registry_username"></a> [kots\_registry\_username](#input\_kots\_registry\_username) | The registry username to use for airgap installation. | `string` | `""` | no |
| <a name="input_license_file"></a> [license\_file](#input\_license\_file) | The path to the license file to use | `string` | n/a | yes |
| <a name="input_load_balancer_controller_iam_role_arn"></a> [load\_balancer\_controller\_iam\_role\_arn](#input\_load\_balancer\_controller\_iam\_role\_arn) | n/a | `string` | n/a | yes |
| <a name="input_ms_replica_count"></a> [ms\_replica\_count](#input\_ms\_replica\_count) | The microservices replica count (e.g. a minimum) | `number` | `3` | no |
| <a name="input_network_load_balancer_scheme"></a> [network\_load\_balancer\_scheme](#input\_network\_load\_balancer\_scheme) | The load balancer scheme. | `string` | `"internet-facing"` | no |
| <a name="input_nodegroup_iam_role_name"></a> [nodegroup\_iam\_role\_name](#input\_nodegroup\_iam\_role\_name) | n/a | `string` | n/a | yes |
| <a name="input_object_storage_access_key"></a> [object\_storage\_access\_key](#input\_object\_storage\_access\_key) | The S3 access key to use to access buckets | `string` | n/a | yes |
| <a name="input_object_storage_endpoint"></a> [object\_storage\_endpoint](#input\_object\_storage\_endpoint) | The S3 endpoint to use to access buckets | `string` | n/a | yes |
| <a name="input_object_storage_secret_key"></a> [object\_storage\_secret\_key](#input\_object\_storage\_secret\_key) | The S3 secret key to use to access buckets | `string` | n/a | yes |
| <a name="input_pod_eniconfig"></a> [pod\_eniconfig](#input\_pod\_eniconfig) | The ENIConfigs for EKS custom networking configuration. | `string` | n/a | yes |
| <a name="input_postgres_database_name"></a> [postgres\_database\_name](#input\_postgres\_database\_name) | The name of the main database. | `string` | `"ast"` | no |
| <a name="input_postgres_host"></a> [postgres\_host](#input\_postgres\_host) | The endpoint for the main RDS server. | `string` | n/a | yes |
| <a name="input_postgres_password"></a> [postgres\_password](#input\_postgres\_password) | The user name for the main RDS server. | `string` | `"ast"` | no |
| <a name="input_postgres_read_host"></a> [postgres\_read\_host](#input\_postgres\_read\_host) | The endpoint for the main RDS server readonly endpoint. | `string` | `null` | no |
| <a name="input_postgres_user"></a> [postgres\_user](#input\_postgres\_user) | The user name for the main RDS server. | `string` | `"ast"` | no |
| <a name="input_redis_address"></a> [redis\_address](#input\_redis\_address) | The redis endpoint. | `string` | n/a | yes |
| <a name="input_redis_auth_token"></a> [redis\_auth\_token](#input\_redis\_auth\_token) | The REDIS Auth token. | `string` | `""` | no |
| <a name="input_redis_port"></a> [redis\_port](#input\_redis\_port) | The redis port | `string` | `"6379"` | no |
| <a name="input_redis_tls_enabled"></a> [redis\_tls\_enabled](#input\_redis\_tls\_enabled) | Enables REDIS TLS connections. | `bool` | `false` | no |
| <a name="input_redis_tls_skipverify"></a> [redis\_tls\_skipverify](#input\_redis\_tls\_skipverify) | Skip verification of REDIS TLS connections. | `bool` | `true` | no |
| <a name="input_region"></a> [region](#input\_region) | The AWS region e.g. us-east-1, us-west-2, etc. | `string` | n/a | yes |
| <a name="input_release_channel"></a> [release\_channel](#input\_release\_channel) | The release channel to deploy from | `string` | n/a | yes |
| <a name="input_sca_client_secret"></a> [sca\_client\_secret](#input\_sca\_client\_secret) | The SCA client secret for the system. Autogenerated if left unspecified. | `string` | `null` | no |
| <a name="input_sca_prod_environment"></a> [sca\_prod\_environment](#input\_sca\_prod\_environment) | The SCA API endpoint to configure. Options are https://api-sca.checkmarx.net and https://eu.api-sca.checkmarx.net. | `string` | `"https://api-sca.checkmarx.net"` | no |
| <a name="input_smtp_from_sender"></a> [smtp\_from\_sender](#input\_smtp\_from\_sender) | The address to use in the from field when sending emails. | `string` | n/a | yes |
| <a name="input_smtp_host"></a> [smtp\_host](#input\_smtp\_host) | The hostname of the SMTP server. | `string` | n/a | yes |
| <a name="input_smtp_password"></a> [smtp\_password](#input\_smtp\_password) | The smtp password. | `string` | n/a | yes |
| <a name="input_smtp_port"></a> [smtp\_port](#input\_smtp\_port) | The port of the SMTP server. | `number` | n/a | yes |
| <a name="input_smtp_user"></a> [smtp\_user](#input\_smtp\_user) | The smtp user name. | `string` | n/a | yes |
| <a name="input_vpc_id"></a> [vpc\_id](#input\_vpc\_id) | The VPC Id Checkmarx One is deployed into. | `string` | n/a | yes |

## Outputs

No outputs.
<!-- END_TF_DOCS -->