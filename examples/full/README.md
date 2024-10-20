# Full Example

This folder contains a full example for deploying [Checkmarx One](https://checkmarx.com/product/application-security-platform/) on [AWS](https://aws.amazon.com) using [Terraform](https://www.terraform.io). 

The project configures the VPC, KMS, ACM, and other basic environment resources, and then invokes the `terraform-aws-cxone` module to deploy Checkmarx One infrastructure. The [`cxone-install`](../../modules/cxone-install) module is used to generate installation scripts for the application after Terraform deploys the infrastructure.

Consult the [`example.auto.tfvars`](./example.auto.tfvars) for a full listing of what can be configured in this example, and the `terraform-aws-cxone module`.

# Installation
This example generates a `Makefile` in the project folder after Terraform finishes running. The Makefile has several targets that can help bootstrap your environment with the CxOne application. 

The `kots.$DEPLOYMENT_ID.yaml` file is also automatically generated and can be reviewed & modified after Terraform finishes.

Run these commands to bootstrap your cluster using the generated files.

Update your kubectl context:

```sh
make update-kubeconfig
```

Update the EKS storage configuration to default to gp3:

```sh
make apply-storageclass-config
```

Install the cluster autoscaler:
```sh
make install-cluster-autoscaler
```

Install the load balancer controller (wait approx 1 minute after cluster autoscaler to avoid webhook issues):
```sh
make install-load-balancer-controller
```

Install the external dns if you're using it (wait approx 1 minute after cluster autoscaler to avoid webhook issues):
```sh
make install-external-dns
```

Manually review your kots configuration file and make any adjustments, if needed.

Install the Checkmarx One application:
```sh
make kots-install
```

You can also build your own installation process using your organization's tooling and techniques using the Makefile as a reference.

# Module Documentation
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_helm"></a> [helm](#requirement\_helm) | ~> 2.13.0 |
| <a name="requirement_kubernetes"></a> [kubernetes](#requirement\_kubernetes) | ~> 2.30.0 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | n/a |
| <a name="provider_random"></a> [random](#provider\_random) | n/a |

## Modules

| Name | Source | Version |
|------|--------|---------|
| <a name="module_acm"></a> [acm](#module\_acm) | terraform-aws-modules/acm/aws | 5.0.1 |
| <a name="module_checkmarx-one"></a> [checkmarx-one](#module\_checkmarx-one) | ../../ | n/a |
| <a name="module_checkmarx-one-install"></a> [checkmarx-one-install](#module\_checkmarx-one-install) | ../../modules/cxone-install | n/a |
| <a name="module_vpc"></a> [vpc](#module\_vpc) | ../../modules/inspection-vpc | n/a |

## Resources

| Name | Type |
|------|------|
| [aws_kms_key.main](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_key) | resource |
| [random_password.analytics_db](https://registry.terraform.io/providers/hashicorp/random/latest/docs/resources/password) | resource |
| [random_password.cxone_admin](https://registry.terraform.io/providers/hashicorp/random/latest/docs/resources/password) | resource |
| [random_password.db](https://registry.terraform.io/providers/hashicorp/random/latest/docs/resources/password) | resource |
| [random_password.elasticsearch](https://registry.terraform.io/providers/hashicorp/random/latest/docs/resources/password) | resource |
| [random_password.kots_admin](https://registry.terraform.io/providers/hashicorp/random/latest/docs/resources/password) | resource |
| [aws_availability_zones.available](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/availability_zones) | data source |
| [aws_caller_identity.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/caller_identity) | data source |
| [aws_partition.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/partition) | data source |
| [aws_region.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/region) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_acm_certificate_arn"></a> [acm\_certificate\_arn](#input\_acm\_certificate\_arn) | The ARN to the SSL certificate in AWS ACM to use for securing the load balancer | `string` | `null` | no |
| <a name="input_additional_suricata_rules"></a> [additional\_suricata\_rules](#input\_additional\_suricata\_rules) | Additional [suricata rules](https://docs.aws.amazon.com/network-firewall/latest/developerguide/suricata-examples.html) rules to use in the network firewall. When provided these rules will be appended to the default rules prior to the default drop rule. | `string` | `""` | no |
| <a name="input_analytics_db_cluster_db_instance_parameter_group_name"></a> [analytics\_db\_cluster\_db\_instance\_parameter\_group\_name](#input\_analytics\_db\_cluster\_db\_instance\_parameter\_group\_name) | The name of the DB Cluster parameter group to use. | `string` | `null` | no |
| <a name="input_analytics_db_final_snapshot_identifier"></a> [analytics\_db\_final\_snapshot\_identifier](#input\_analytics\_db\_final\_snapshot\_identifier) | Identifer for a final DB snapshot for the analytics database. Required when db\_skip\_final\_snapshot is false.. | `string` | `null` | no |
| <a name="input_analytics_db_instance_class"></a> [analytics\_db\_instance\_class](#input\_analytics\_db\_instance\_class) | The aurora postgres instance class. | `string` | `"db.r6g.xlarge"` | no |
| <a name="input_analytics_db_instances"></a> [analytics\_db\_instances](#input\_analytics\_db\_instances) | The DB instance configuration | `map(any)` | <pre>{<br>  "replica1": {},<br>  "writer": {}<br>}</pre> | no |
| <a name="input_analytics_db_master_user_password"></a> [analytics\_db\_master\_user\_password](#input\_analytics\_db\_master\_user\_password) | The master user password for RDS. Specify to explicitly set the password otherwise RDS will be allowed to manage it. | `string` | `null` | no |
| <a name="input_analytics_db_serverlessv2_scaling_configuration"></a> [analytics\_db\_serverlessv2\_scaling\_configuration](#input\_analytics\_db\_serverlessv2\_scaling\_configuration) | The serverless v2 scaling minimum and maximum. | <pre>object({<br>    min_capacity = number<br>    max_capacity = number<br>  })</pre> | <pre>{<br>  "max_capacity": 32,<br>  "min_capacity": 0.5<br>}</pre> | no |
| <a name="input_analytics_db_snapshot_identifer"></a> [analytics\_db\_snapshot\_identifer](#input\_analytics\_db\_snapshot\_identifer) | The snapshot identifier to restore the anatlytics database from. | `string` | `null` | no |
| <a name="input_aws_ebs_csi_driver_version"></a> [aws\_ebs\_csi\_driver\_version](#input\_aws\_ebs\_csi\_driver\_version) | The version of the EKS EBS CSI Addon. | `string` | n/a | yes |
| <a name="input_coredns_version"></a> [coredns\_version](#input\_coredns\_version) | The version of the EKS Core DNS Addon. | `string` | n/a | yes |
| <a name="input_create_interface_endpoints"></a> [create\_interface\_endpoints](#input\_create\_interface\_endpoints) | Enables creation of the [interface endpoints](https://docs.aws.amazon.com/vpc/latest/privatelink/privatelink-access-aws-services.html) specified in `interface_vpc_endpoints` | `bool` | `true` | no |
| <a name="input_create_managed_rule_groups"></a> [create\_managed\_rule\_groups](#input\_create\_managed\_rule\_groups) | Enables creation of the AWS Network Firewall [managed rule groups](https://docs.aws.amazon.com/network-firewall/latest/developerguide/aws-managed-rule-groups-list.html) provided in `managed_rule_groups` | `bool` | `true` | no |
| <a name="input_create_s3_endpoint"></a> [create\_s3\_endpoint](#input\_create\_s3\_endpoint) | Enables creation of the [s3 gateway VPC endpoint](https://docs.aws.amazon.com/vpc/latest/privatelink/vpc-endpoints-s3.html) | `bool` | `true` | no |
| <a name="input_db_allow_major_version_upgrade"></a> [db\_allow\_major\_version\_upgrade](#input\_db\_allow\_major\_version\_upgrade) | Allows major version upgrades. | `bool` | `false` | no |
| <a name="input_db_apply_immediately"></a> [db\_apply\_immediately](#input\_db\_apply\_immediately) | Determines if changes will be applied immediately or wait until the next maintenance window. | `bool` | `false` | no |
| <a name="input_db_auto_minor_version_upgrade"></a> [db\_auto\_minor\_version\_upgrade](#input\_db\_auto\_minor\_version\_upgrade) | Automatically upgrade to latest minor version in maintenance window. | `bool` | `false` | no |
| <a name="input_db_autoscaling_enabled"></a> [db\_autoscaling\_enabled](#input\_db\_autoscaling\_enabled) | Enables autoscaling of the aurora database. | `bool` | `true` | no |
| <a name="input_db_autoscaling_max_capacity"></a> [db\_autoscaling\_max\_capacity](#input\_db\_autoscaling\_max\_capacity) | The maximum number of replicas via autoscaling. | `string` | `"3"` | no |
| <a name="input_db_autoscaling_min_capacity"></a> [db\_autoscaling\_min\_capacity](#input\_db\_autoscaling\_min\_capacity) | The minimum number of replicas via autoscaling. | `string` | `"1"` | no |
| <a name="input_db_autoscaling_scale_in_cooldown"></a> [db\_autoscaling\_scale\_in\_cooldown](#input\_db\_autoscaling\_scale\_in\_cooldown) | The database scale in cooldown period. | `number` | `300` | no |
| <a name="input_db_autoscaling_scale_out_cooldown"></a> [db\_autoscaling\_scale\_out\_cooldown](#input\_db\_autoscaling\_scale\_out\_cooldown) | The database scale ou cooldown period. | `number` | `300` | no |
| <a name="input_db_autoscaling_target_cpu"></a> [db\_autoscaling\_target\_cpu](#input\_db\_autoscaling\_target\_cpu) | The CPU utilization for autoscaling target tracking. | `number` | `70` | no |
| <a name="input_db_cluster_db_instance_parameter_group_name"></a> [db\_cluster\_db\_instance\_parameter\_group\_name](#input\_db\_cluster\_db\_instance\_parameter\_group\_name) | The name of the DB Cluster parameter group to use. | `string` | `null` | no |
| <a name="input_db_create"></a> [db\_create](#input\_db\_create) | Controls creation of the Aurora postgres database. | `bool` | `true` | no |
| <a name="input_db_create_rds_proxy"></a> [db\_create\_rds\_proxy](#input\_db\_create\_rds\_proxy) | Enables an RDS proxy for the Aurora postgres database. | `bool` | `true` | no |
| <a name="input_db_deletion_protection"></a> [db\_deletion\_protection](#input\_db\_deletion\_protection) | Enables deletion protection to avoid accidental database deletion. | `bool` | `true` | no |
| <a name="input_db_engine_version"></a> [db\_engine\_version](#input\_db\_engine\_version) | The aurora postgres engine version. | `string` | `"13.8"` | no |
| <a name="input_db_final_snapshot_identifier"></a> [db\_final\_snapshot\_identifier](#input\_db\_final\_snapshot\_identifier) | Identifer for a final DB snapshot. Required when db\_skip\_final\_snapshot is false.. | `string` | `null` | no |
| <a name="input_db_instance_class"></a> [db\_instance\_class](#input\_db\_instance\_class) | The aurora postgres instance class. | `string` | `"db.r6g.xlarge"` | no |
| <a name="input_db_instances"></a> [db\_instances](#input\_db\_instances) | The DB instance configuration | `map(any)` | <pre>{<br>  "replica1": {},<br>  "writer": {}<br>}</pre> | no |
| <a name="input_db_master_user_password"></a> [db\_master\_user\_password](#input\_db\_master\_user\_password) | The master user password for RDS. Specify to explicitly set the password otherwise RDS will be allowed to manage it. | `string` | `null` | no |
| <a name="input_db_monitoring_interval"></a> [db\_monitoring\_interval](#input\_db\_monitoring\_interval) | The aurora postgres engine version. | `string` | `"10"` | no |
| <a name="input_db_performance_insights_enabled"></a> [db\_performance\_insights\_enabled](#input\_db\_performance\_insights\_enabled) | Enables database performance insights. | `bool` | `true` | no |
| <a name="input_db_performance_insights_retention_period"></a> [db\_performance\_insights\_retention\_period](#input\_db\_performance\_insights\_retention\_period) | Number of days to retain performance insights data. Free tier: 7 days. | `number` | `7` | no |
| <a name="input_db_port"></a> [db\_port](#input\_db\_port) | The port on which the DB accepts connections. | `string` | `"5432"` | no |
| <a name="input_db_serverlessv2_scaling_configuration"></a> [db\_serverlessv2\_scaling\_configuration](#input\_db\_serverlessv2\_scaling\_configuration) | The serverless v2 scaling minimum and maximum. | <pre>object({<br>    min_capacity = number<br>    max_capacity = number<br>  })</pre> | <pre>{<br>  "max_capacity": 32,<br>  "min_capacity": 0.5<br>}</pre> | no |
| <a name="input_db_skip_final_snapshot"></a> [db\_skip\_final\_snapshot](#input\_db\_skip\_final\_snapshot) | Enables skipping the final snapshot upon deletion. | `bool` | `false` | no |
| <a name="input_db_snapshot_identifer"></a> [db\_snapshot\_identifer](#input\_db\_snapshot\_identifer) | The snapshot identifier to restore the database from. | `string` | `null` | no |
| <a name="input_deployment_id"></a> [deployment\_id](#input\_deployment\_id) | The id of the deployment. Will be used to name resources like EKS cluster, etc. | `string` | n/a | yes |
| <a name="input_ec2_key_name"></a> [ec2\_key\_name](#input\_ec2\_key\_name) | The name of the EC2 key pair to access servers. | `string` | `null` | no |
| <a name="input_ec_auto_minor_version_upgrade"></a> [ec\_auto\_minor\_version\_upgrade](#input\_ec\_auto\_minor\_version\_upgrade) | Enables automatic minor version upgrades. Does not apply to serverless. | `bool` | `false` | no |
| <a name="input_ec_automatic_failover_enabled"></a> [ec\_automatic\_failover\_enabled](#input\_ec\_automatic\_failover\_enabled) | Enables automatic failover. Does not apply to serverless. | `bool` | `true` | no |
| <a name="input_ec_create"></a> [ec\_create](#input\_ec\_create) | Enables the creation of elasticache resources. | `bool` | `true` | no |
| <a name="input_ec_enable_serverless"></a> [ec\_enable\_serverless](#input\_ec\_enable\_serverless) | Enables the use of elasticache for redis serverless. | `bool` | `false` | no |
| <a name="input_ec_engine_version"></a> [ec\_engine\_version](#input\_ec\_engine\_version) | The version of the elasticache cluster. Does not apply to serverless. | `string` | `"6.x"` | no |
| <a name="input_ec_multi_az_enabled"></a> [ec\_multi\_az\_enabled](#input\_ec\_multi\_az\_enabled) | Enables automatic failover. Does not apply to serverless. | `bool` | `true` | no |
| <a name="input_ec_node_type"></a> [ec\_node\_type](#input\_ec\_node\_type) | The elasticache redis node type. Does not apply to serverless. | `string` | `"cache.m6g.large"` | no |
| <a name="input_ec_number_of_shards"></a> [ec\_number\_of\_shards](#input\_ec\_number\_of\_shards) | The number of shards for redis. Does not apply to serverless. | `number` | `3` | no |
| <a name="input_ec_parameter_group_name"></a> [ec\_parameter\_group\_name](#input\_ec\_parameter\_group\_name) | The elasticache parameter group name. Does not apply to serverless. | `string` | `"default.redis6.x.cluster.on"` | no |
| <a name="input_ec_replicas_per_shard"></a> [ec\_replicas\_per\_shard](#input\_ec\_replicas\_per\_shard) | The number of replicas per shard for redis. Does not apply to serverless. | `number` | `2` | no |
| <a name="input_ec_serverless_max_ecpu_per_second"></a> [ec\_serverless\_max\_ecpu\_per\_second](#input\_ec\_serverless\_max\_ecpu\_per\_second) | The max eCPU per second for serverless elasticache for redis. | `number` | `5000` | no |
| <a name="input_ec_serverless_max_storage"></a> [ec\_serverless\_max\_storage](#input\_ec\_serverless\_max\_storage) | The max storage, in GB, for serverless elasticache for redis. | `number` | `5` | no |
| <a name="input_eks_administrator_principals"></a> [eks\_administrator\_principals](#input\_eks\_administrator\_principals) | The ARNs of the IAM roles for administrator access to EKS. | <pre>list(object({<br>    name          = string<br>    principal_arn = string<br>  }))</pre> | `[]` | no |
| <a name="input_eks_cluster_endpoint_public_access_cidrs"></a> [eks\_cluster\_endpoint\_public\_access\_cidrs](#input\_eks\_cluster\_endpoint\_public\_access\_cidrs) | List of CIDR blocks which can access the Amazon EKS public API server endpoint | `list(string)` | <pre>[<br>  "0.0.0.0/0"<br>]</pre> | no |
| <a name="input_eks_create"></a> [eks\_create](#input\_eks\_create) | Enables the EKS resource creation | `bool` | `true` | no |
| <a name="input_eks_create_cluster_autoscaler_irsa"></a> [eks\_create\_cluster\_autoscaler\_irsa](#input\_eks\_create\_cluster\_autoscaler\_irsa) | Enables creation of cluster autoscaler IAM role. | `bool` | `true` | no |
| <a name="input_eks_create_external_dns_irsa"></a> [eks\_create\_external\_dns\_irsa](#input\_eks\_create\_external\_dns\_irsa) | Enables creation of external dns IAM role. | `bool` | `true` | no |
| <a name="input_eks_create_karpenter"></a> [eks\_create\_karpenter](#input\_eks\_create\_karpenter) | Enables creation of Karpenter resources. | `bool` | `false` | no |
| <a name="input_eks_create_load_balancer_controller_irsa"></a> [eks\_create\_load\_balancer\_controller\_irsa](#input\_eks\_create\_load\_balancer\_controller\_irsa) | Enables creation of load balancer controller IAM role. | `bool` | `true` | no |
| <a name="input_eks_enable_custom_networking"></a> [eks\_enable\_custom\_networking](#input\_eks\_enable\_custom\_networking) | Enables custom networking for the EKS VPC CNI. When true, custom networking is enabled with `ENI_CONFIG_LABEL_DEF` = `topology.kubernetes.io/zone` and ENIConfig resources must be created. | `bool` | `false` | no |
| <a name="input_eks_enable_externalsnat"></a> [eks\_enable\_externalsnat](#input\_eks\_enable\_externalsnat) | Enables [External SNAT](https://docs.aws.amazon.com/eks/latest/userguide/external-snat.html) for the EKS VPC CNI. When true, the EKS pods must have a route to a NAT Gateway for outbound communication. | `bool` | `false` | no |
| <a name="input_eks_enable_fargate"></a> [eks\_enable\_fargate](#input\_eks\_enable\_fargate) | Enables Fargate profiles for the karpenter and kube-system namespaces. | `bool` | `false` | no |
| <a name="input_eks_node_additional_security_group_ids"></a> [eks\_node\_additional\_security\_group\_ids](#input\_eks\_node\_additional\_security\_group\_ids) | Additional security group ids to attach to EKS nodes. | `list(string)` | `[]` | no |
| <a name="input_eks_node_groups"></a> [eks\_node\_groups](#input\_eks\_node\_groups) | n/a | <pre>list(object({<br>    name            = string<br>    min_size        = string<br>    desired_size    = string<br>    max_size        = string<br>    volume_type     = optional(string, "gp3")<br>    disk_size       = optional(number, 200)<br>    disk_iops       = optional(number, 3000)<br>    disk_throughput = optional(number, 125)<br>    device_name     = optional(string, "/dev/xvda")<br>    instance_types  = list(string)<br>    capacity_type   = optional(string, "ON_DEMAND")<br>    labels          = optional(map(string), {})<br>    taints          = optional(map(object({ key = string, value = string, effect = string })), {})<br>  }))</pre> | <pre>[<br>  {<br>    "desired_size": 3,<br>    "instance_types": [<br>      "c5.4xlarge"<br>    ],<br>    "max_size": 9,<br>    "min_size": 3,<br>    "name": "ast-app"<br>  },<br>  {<br>    "desired_size": 0,<br>    "instance_types": [<br>      "m5.2xlarge"<br>    ],<br>    "labels": {<br>      "sast-engine": "true"<br>    },<br>    "max_size": 100,<br>    "min_size": 0,<br>    "name": "sast-engine",<br>    "taints": {<br>      "dedicated": {<br>        "effect": "NO_SCHEDULE",<br>        "key": "sast-engine",<br>        "value": "true"<br>      }<br>    }<br>  },<br>  {<br>    "desired_size": 0,<br>    "instance_types": [<br>      "m5.4xlarge"<br>    ],<br>    "labels": {<br>      "sast-engine-large": "true"<br>    },<br>    "max_size": 100,<br>    "min_size": 0,<br>    "name": "sast-engine-large",<br>    "taints": {<br>      "dedicated": {<br>        "effect": "NO_SCHEDULE",<br>        "key": "sast-engine-large",<br>        "value": "true"<br>      }<br>    }<br>  },<br>  {<br>    "desired_size": 0,<br>    "instance_types": [<br>      "r5.2xlarge"<br>    ],<br>    "labels": {<br>      "sast-engine-extra-large": "true"<br>    },<br>    "max_size": 100,<br>    "min_size": 0,<br>    "name": "sast-engine-extra-large",<br>    "taints": {<br>      "dedicated": {<br>        "effect": "NO_SCHEDULE",<br>        "key": "sast-engine-extra-large",<br>        "value": "true"<br>      }<br>    }<br>  },<br>  {<br>    "desired_size": 0,<br>    "instance_types": [<br>      "r5.4xlarge"<br>    ],<br>    "labels": {<br>      "sast-engine-xxl": "true"<br>    },<br>    "max_size": 100,<br>    "min_size": 0,<br>    "name": "sast-engine-xxl",<br>    "taints": {<br>      "dedicated": {<br>        "effect": "NO_SCHEDULE",<br>        "key": "sast-engine-xxl",<br>        "value": "true"<br>      }<br>    }<br>  },<br>  {<br>    "desired_size": 1,<br>    "instance_types": [<br>      "c5.2xlarge"<br>    ],<br>    "labels": {<br>      "kics-engine": "true"<br>    },<br>    "max_size": 100,<br>    "min_size": 1,<br>    "name": "kics-engine",<br>    "taints": {<br>      "dedicated": {<br>        "effect": "NO_SCHEDULE",<br>        "key": "kics-engine",<br>        "value": "true"<br>      }<br>    }<br>  },<br>  {<br>    "desired_size": 1,<br>    "instance_types": [<br>      "c5.2xlarge"<br>    ],<br>    "labels": {<br>      "repostore": "true"<br>    },<br>    "max_size": 100,<br>    "min_size": 1,<br>    "name": "repostore",<br>    "taints": {<br>      "dedicated": {<br>        "effect": "NO_SCHEDULE",<br>        "key": "repostore",<br>        "value": "true"<br>      }<br>    }<br>  },<br>  {<br>    "desired_size": 0,<br>    "instance_types": [<br>      "m5.2xlarge"<br>    ],<br>    "labels": {<br>      "service": "sca-source-resolver"<br>    },<br>    "max_size": 100,<br>    "min_size": 0,<br>    "name": "sca-source-resolver",<br>    "taints": {<br>      "dedicated": {<br>        "effect": "NO_SCHEDULE",<br>        "key": "service",<br>        "value": "sca-source-resolver"<br>      }<br>    }<br>  }<br>]</pre> | no |
| <a name="input_eks_post_bootstrap_user_data"></a> [eks\_post\_bootstrap\_user\_data](#input\_eks\_post\_bootstrap\_user\_data) | User data to insert after bootstrapping script. | `string` | `""` | no |
| <a name="input_eks_pre_bootstrap_user_data"></a> [eks\_pre\_bootstrap\_user\_data](#input\_eks\_pre\_bootstrap\_user\_data) | User data to insert before bootstrapping script. | `string` | `""` | no |
| <a name="input_eks_private_endpoint_enabled"></a> [eks\_private\_endpoint\_enabled](#input\_eks\_private\_endpoint\_enabled) | Enables the EKS VPC private endpoint. | `bool` | `true` | no |
| <a name="input_eks_public_endpoint_enabled"></a> [eks\_public\_endpoint\_enabled](#input\_eks\_public\_endpoint\_enabled) | Enables the EKS public endpoint. | `bool` | `false` | no |
| <a name="input_eks_version"></a> [eks\_version](#input\_eks\_version) | The version of the EKS Cluster (e.g. 1.27) | `string` | n/a | yes |
| <a name="input_enable_cluster_creator_admin_permissions"></a> [enable\_cluster\_creator\_admin\_permissions](#input\_enable\_cluster\_creator\_admin\_permissions) | Enables the identity used to create the EKS cluster to have administrator access to that EKS cluster. When enabled, do not specify the same principal arn for eks\_administrator\_principals. | `bool` | `true` | no |
| <a name="input_enable_firewall"></a> [enable\_firewall](#input\_enable\_firewall) | Enables the use of the [AWS Network Firewall](https://docs.aws.amazon.com/network-firewall/latest/developerguide/what-is-aws-network-firewall.html) to protect the private and pod subnets | `bool` | `true` | no |
| <a name="input_es_create"></a> [es\_create](#input\_es\_create) | Enables creation of elasticsearch resources. | `bool` | `true` | no |
| <a name="input_es_instance_count"></a> [es\_instance\_count](#input\_es\_instance\_count) | The number of nodes in elasticsearch cluster | `number` | `2` | no |
| <a name="input_es_instance_type"></a> [es\_instance\_type](#input\_es\_instance\_type) | The instance type for elasticsearch nodes. | `string` | `"r6g.large.elasticsearch"` | no |
| <a name="input_es_tls_security_policy"></a> [es\_tls\_security\_policy](#input\_es\_tls\_security\_policy) | n/a | `string` | `"Policy-Min-TLS-1-2-2019-07"` | no |
| <a name="input_es_username"></a> [es\_username](#input\_es\_username) | The username for the elasticsearch user | `string` | `"ast"` | no |
| <a name="input_es_volume_size"></a> [es\_volume\_size](#input\_es\_volume\_size) | The size of volumes for nodes in elasticsearch cluster | `number` | `100` | no |
| <a name="input_fqdn"></a> [fqdn](#input\_fqdn) | The fully qualified domain name that will be used for the Checkmarx One deployment | `string` | n/a | yes |
| <a name="input_include_sca_rules"></a> [include\_sca\_rules](#input\_include\_sca\_rules) | Enables inclusion of AWS Network Firewall rules used in SCA scanning. These rules may be overly permissive when not using SCA, so they are optional. These rules allow connectivity to various public package manager repositories like [Maven Central](https://mvnrepository.com/repos/central) and [npm](https://docs.npmjs.com/). | `bool` | `true` | no |
| <a name="input_interface_vpc_endpoints"></a> [interface\_vpc\_endpoints](#input\_interface\_vpc\_endpoints) | A list of AWS services to create [VPC Private Endpoints](https://docs.aws.amazon.com/vpc/latest/privatelink/privatelink-access-aws-services.html) for. These endpoints are used for communication direct to AWS services without requiring connectivity and are useful for private EKS clusters. | `list(string)` | <pre>[<br>  "ec2",<br>  "ec2messages",<br>  "ssm",<br>  "ssmmessages",<br>  "ecr.api",<br>  "ecr.dkr",<br>  "kms",<br>  "logs",<br>  "sts",<br>  "elasticloadbalancing",<br>  "autoscaling"<br>]</pre> | no |
| <a name="input_kots_admin_email"></a> [kots\_admin\_email](#input\_kots\_admin\_email) | The email address of the Checkmarx One first admin user. | `string` | n/a | yes |
| <a name="input_kots_cxone_version"></a> [kots\_cxone\_version](#input\_kots\_cxone\_version) | The version of Checkmarx One to install | `string` | n/a | yes |
| <a name="input_kots_license_file"></a> [kots\_license\_file](#input\_kots\_license\_file) | The path to the kots license file to install Checkamrx One with. | `string` | n/a | yes |
| <a name="input_kots_release_channel"></a> [kots\_release\_channel](#input\_kots\_release\_channel) | The release channel from which to install Checkmarx One | `string` | `"beta"` | no |
| <a name="input_kube_proxy_version"></a> [kube\_proxy\_version](#input\_kube\_proxy\_version) | The version of the EKS Kube Proxy Addon. | `string` | n/a | yes |
| <a name="input_launch_template_tags"></a> [launch\_template\_tags](#input\_launch\_template\_tags) | Tags to associate with launch templates for node groups | `map(string)` | `null` | no |
| <a name="input_managed_rule_groups"></a> [managed\_rule\_groups](#input\_managed\_rule\_groups) | The AWS Network Firewall [managed rule groups](https://docs.aws.amazon.com/network-firewall/latest/developerguide/aws-managed-rule-groups-list.html) to include in the firewall policy. Must be strict order groups. | `list(string)` | <pre>[<br>  "AbusedLegitMalwareDomainsStrictOrder",<br>  "MalwareDomainsStrictOrder",<br>  "AbusedLegitBotNetCommandAndControlDomainsStrictOrder",<br>  "BotNetCommandAndControlDomainsStrictOrder",<br>  "ThreatSignaturesBotnetStrictOrder",<br>  "ThreatSignaturesBotnetWebStrictOrder",<br>  "ThreatSignaturesBotnetWindowsStrictOrder",<br>  "ThreatSignaturesIOCStrictOrder",<br>  "ThreatSignaturesDoSStrictOrder",<br>  "ThreatSignaturesEmergingEventsStrictOrder",<br>  "ThreatSignaturesExploitsStrictOrder",<br>  "ThreatSignaturesMalwareStrictOrder",<br>  "ThreatSignaturesMalwareCoinminingStrictOrder",<br>  "ThreatSignaturesMalwareMobileStrictOrder",<br>  "ThreatSignaturesMalwareWebStrictOrder",<br>  "ThreatSignaturesScannersStrictOrder",<br>  "ThreatSignaturesSuspectStrictOrder",<br>  "ThreatSignaturesWebAttacksStrictOrder"<br>]</pre> | no |
| <a name="input_ms_replica_count"></a> [ms\_replica\_count](#input\_ms\_replica\_count) | The microservices replica count (e.g. a minimum) | `number` | `3` | no |
| <a name="input_object_storage_access_key"></a> [object\_storage\_access\_key](#input\_object\_storage\_access\_key) | The S3 access key to use to access buckets | `string` | n/a | yes |
| <a name="input_object_storage_endpoint"></a> [object\_storage\_endpoint](#input\_object\_storage\_endpoint) | The S3 endpoint to use to access buckets | `string` | n/a | yes |
| <a name="input_object_storage_secret_key"></a> [object\_storage\_secret\_key](#input\_object\_storage\_secret\_key) | The S3 secret key to use to access buckets | `string` | n/a | yes |
| <a name="input_primary_cidr_block"></a> [primary\_cidr\_block](#input\_primary\_cidr\_block) | The primary VPC CIDR block for the VPC. Must be at least a /19. | `string` | n/a | yes |
| <a name="input_route_53_hosted_zone_id"></a> [route\_53\_hosted\_zone\_id](#input\_route\_53\_hosted\_zone\_id) | The hosted zone id for route 53 in which to create dns and certificates. | `string` | n/a | yes |
| <a name="input_s3_retention_period"></a> [s3\_retention\_period](#input\_s3\_retention\_period) | The retention period, in days, to retain s3 objects. | `string` | `"90"` | no |
| <a name="input_secondary_cidr_block"></a> [secondary\_cidr\_block](#input\_secondary\_cidr\_block) | The secondary VPC CIDR block for the EKS Pod [Custom Networking](https://aws.github.io/aws-eks-best-practices/networking/custom-networking/) configuration. Must be at least a /18. | `string` | `"100.64.0.0/18"` | no |
| <a name="input_smtp_from_sender"></a> [smtp\_from\_sender](#input\_smtp\_from\_sender) | The address to use in the from field when sending emails. | `string` | n/a | yes |
| <a name="input_smtp_host"></a> [smtp\_host](#input\_smtp\_host) | The hostname of the SMTP server. | `string` | n/a | yes |
| <a name="input_smtp_password"></a> [smtp\_password](#input\_smtp\_password) | The smtp password. | `string` | n/a | yes |
| <a name="input_smtp_port"></a> [smtp\_port](#input\_smtp\_port) | The port of the SMTP server. | `number` | `587` | no |
| <a name="input_smtp_user"></a> [smtp\_user](#input\_smtp\_user) | The smtp user name. | `string` | n/a | yes |
| <a name="input_stateful_default_action"></a> [stateful\_default\_action](#input\_stateful\_default\_action) | The [default action](https://docs.aws.amazon.com/network-firewall/latest/developerguide/suricata-rule-evaluation-order.html#suricata-strict-rule-evaluation-order) for the AWS Network Firewall stateful rule group. Choose `aws:drop_established` or `aws:alert_established` | `string` | `"aws:drop_established"` | no |
| <a name="input_suricata_rules"></a> [suricata\_rules](#input\_suricata\_rules) | The [suricata rules](https://docs.aws.amazon.com/network-firewall/latest/developerguide/suricata-examples.html) to use for the AWS Network Firewall. When provided, this variable completely overrides the embedded rules. Use this to bring your own rules. If you only need to provide some additional rules in addition to the bundled rules, then use `additional_suricata_rules` instead of `suricata_rules`. | `string` | `null` | no |
| <a name="input_vpc_cni_version"></a> [vpc\_cni\_version](#input\_vpc\_cni\_version) | The version of the EKS VPC CNI Addon. | `string` | n/a | yes |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_cxone1"></a> [cxone1](#output\_cxone1) | n/a |