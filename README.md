# terraform-aws-cxone

This repo contains a module for deploying [Checkmarx One](https://checkmarx.com/product/application-security-platform/) on [AWS](https://aws.amazon.com) using [Terraform](https://www.terraform.io). Checkmarx One has everything you need to embed AppSec in every stage of the SDLC, provide an excellent developer experience, integrate with the technologies you use, and build a successful AppSec program.


# Module documentation
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_helm"></a> [helm](#requirement\_helm) | ~> 2.13.0 |
| <a name="requirement_kubernetes"></a> [kubernetes](#requirement\_kubernetes) | ~> 2.30.0 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | n/a |
| <a name="provider_helm"></a> [helm](#provider\_helm) | ~> 2.13.0 |
| <a name="provider_random"></a> [random](#provider\_random) | n/a |

## Modules

| Name | Source | Version |
|------|--------|---------|
| <a name="module_cluster_autoscaler_irsa"></a> [cluster\_autoscaler\_irsa](#module\_cluster\_autoscaler\_irsa) | terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks | 5.39.0 |
| <a name="module_eks"></a> [eks](#module\_eks) | terraform-aws-modules/eks/aws | 20.8.5 |
| <a name="module_eks_node_iam_role"></a> [eks\_node\_iam\_role](#module\_eks\_node\_iam\_role) | terraform-aws-modules/iam/aws//modules/iam-assumable-role | 5.37.2 |
| <a name="module_elasticache_security_group"></a> [elasticache\_security\_group](#module\_elasticache\_security\_group) | terraform-aws-modules/security-group/aws | 5.1.2 |
| <a name="module_elasticsearch_security_group"></a> [elasticsearch\_security\_group](#module\_elasticsearch\_security\_group) | terraform-aws-modules/security-group/aws | 5.1.2 |
| <a name="module_external_dns_irsa"></a> [external\_dns\_irsa](#module\_external\_dns\_irsa) | terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks | 5.39.0 |
| <a name="module_karpenter"></a> [karpenter](#module\_karpenter) | terraform-aws-modules/eks/aws//modules/karpenter | 20.8.5 |
| <a name="module_load_balancer_controller_irsa"></a> [load\_balancer\_controller\_irsa](#module\_load\_balancer\_controller\_irsa) | terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks | 5.39.0 |
| <a name="module_rds"></a> [rds](#module\_rds) | terraform-aws-modules/rds-aurora/aws | 9.3.1 |
| <a name="module_rds-analytics"></a> [rds-analytics](#module\_rds-analytics) | terraform-aws-modules/rds-aurora/aws | 9.3.1 |
| <a name="module_rds-proxy"></a> [rds-proxy](#module\_rds-proxy) | terraform-aws-modules/rds-proxy/aws | 3.1.0 |
| <a name="module_rds-proxy-analytics"></a> [rds-proxy-analytics](#module\_rds-proxy-analytics) | terraform-aws-modules/rds-proxy/aws | 3.1.0 |
| <a name="module_rds_proxy_sg"></a> [rds\_proxy\_sg](#module\_rds\_proxy\_sg) | terraform-aws-modules/security-group/aws | 5.1.2 |
| <a name="module_s3_bucket"></a> [s3\_bucket](#module\_s3\_bucket) | terraform-aws-modules/s3-bucket/aws | 4.1.1 |

## Resources

| Name | Type |
|------|------|
| [aws_autoscaling_group_tag.cluster_autoscaler_label](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/autoscaling_group_tag) | resource |
| [aws_autoscaling_group_tag.cluster_autoscaler_taint](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/autoscaling_group_tag) | resource |
| [aws_db_subnet_group.main](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_subnet_group) | resource |
| [aws_elasticache_replication_group.redis](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticache_replication_group) | resource |
| [aws_elasticache_serverless_cache.main](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticache_serverless_cache) | resource |
| [aws_elasticache_subnet_group.redis](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticache_subnet_group) | resource |
| [aws_elasticsearch_domain.es](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticsearch_domain) | resource |
| [aws_iam_policy.s3_bucket_access](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy) | resource |
| helm_release.analytics-rds-database-preparation | resource |
| [random_string.random_suffix](https://registry.terraform.io/providers/hashicorp/random/latest/docs/resources/string) | resource |
| [aws_caller_identity.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/caller_identity) | data source |
| [aws_iam_role.karpenter](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_role) | data source |
| [aws_partition.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/partition) | data source |
| [aws_region.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/region) | data source |
| [aws_vpc.main](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/vpc) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_analytics_db_cluster_db_instance_parameter_group_name"></a> [analytics\_db\_cluster\_db\_instance\_parameter\_group\_name](#input\_analytics\_db\_cluster\_db\_instance\_parameter\_group\_name) | The name of the DB Cluster parameter group to use. | `string` | `null` | no |
| <a name="input_analytics_db_final_snapshot_identifier"></a> [analytics\_db\_final\_snapshot\_identifier](#input\_analytics\_db\_final\_snapshot\_identifier) | Identifer for a final DB snapshot for the analytics database. Required when db\_skip\_final\_snapshot is false.. | `string` | `null` | no |
| <a name="input_analytics_db_instance_class"></a> [analytics\_db\_instance\_class](#input\_analytics\_db\_instance\_class) | The aurora postgres instance class. | `string` | `"db.r6g.xlarge"` | no |
| <a name="input_analytics_db_instances"></a> [analytics\_db\_instances](#input\_analytics\_db\_instances) | The DB instance configuration | `map(any)` | <pre>{<br>  "replica1": {},<br>  "writer": {}<br>}</pre> | no |
| <a name="input_analytics_db_master_user_password"></a> [analytics\_db\_master\_user\_password](#input\_analytics\_db\_master\_user\_password) | The master user password for RDS. Specify to explicitly set the password otherwise RDS will be allowed to manage it. | `string` | `null` | no |
| <a name="input_analytics_db_serverlessv2_scaling_configuration"></a> [analytics\_db\_serverlessv2\_scaling\_configuration](#input\_analytics\_db\_serverlessv2\_scaling\_configuration) | The serverless v2 scaling minimum and maximum. | <pre>object({<br>    min_capacity = number<br>    max_capacity = number<br>  })</pre> | <pre>{<br>  "max_capacity": 32,<br>  "min_capacity": 0.5<br>}</pre> | no |
| <a name="input_analytics_db_snapshot_identifer"></a> [analytics\_db\_snapshot\_identifer](#input\_analytics\_db\_snapshot\_identifer) | The snapshot identifier to restore the anatlytics database from. | `string` | `null` | no |
| <a name="input_aws_ebs_csi_driver_version"></a> [aws\_ebs\_csi\_driver\_version](#input\_aws\_ebs\_csi\_driver\_version) | The version of the EKS EBS CSI Addon. | `string` | n/a | yes |
| <a name="input_coredns_version"></a> [coredns\_version](#input\_coredns\_version) | The version of the EKS Core DNS Addon. | `string` | n/a | yes |
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
| <a name="input_db_subnets"></a> [db\_subnets](#input\_db\_subnets) | The subnets to deploy RDS into. | `list(string)` | n/a | yes |
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
| <a name="input_ec_subnets"></a> [ec\_subnets](#input\_ec\_subnets) | The subnets to deploy Elasticache into. | `list(string)` | n/a | yes |
| <a name="input_eks_administrator_principals"></a> [eks\_administrator\_principals](#input\_eks\_administrator\_principals) | The ARNs of the IAM roles for administrator access to EKS. | <pre>list(object({<br>    name          = string<br>    principal_arn = string<br>  }))</pre> | `[]` | no |
| <a name="input_eks_cluster_endpoint_public_access_cidrs"></a> [eks\_cluster\_endpoint\_public\_access\_cidrs](#input\_eks\_cluster\_endpoint\_public\_access\_cidrs) | List of CIDR blocks which can access the Amazon EKS public API server endpoint | `list(string)` | <pre>[<br>  "0.0.0.0/0"<br>]</pre> | no |
| <a name="input_eks_cluster_security_group_additional_rules"></a> [eks\_cluster\_security\_group\_additional\_rules](#input\_eks\_cluster\_security\_group\_additional\_rules) | Additional security group rules for the EKS cluster | `any` | `{}` | no |
| <a name="input_eks_create"></a> [eks\_create](#input\_eks\_create) | Enables the EKS resource creation | `bool` | `true` | no |
| <a name="input_eks_create_cluster_autoscaler_irsa"></a> [eks\_create\_cluster\_autoscaler\_irsa](#input\_eks\_create\_cluster\_autoscaler\_irsa) | Enables creation of cluster autoscaler IAM role. | `bool` | `true` | no |
| <a name="input_eks_create_external_dns_irsa"></a> [eks\_create\_external\_dns\_irsa](#input\_eks\_create\_external\_dns\_irsa) | Enables creation of external dns IAM role. | `bool` | `true` | no |
| <a name="input_eks_create_karpenter"></a> [eks\_create\_karpenter](#input\_eks\_create\_karpenter) | Enables creation of Karpenter resources. | `bool` | `false` | no |
| <a name="input_eks_create_load_balancer_controller_irsa"></a> [eks\_create\_load\_balancer\_controller\_irsa](#input\_eks\_create\_load\_balancer\_controller\_irsa) | Enables creation of load balancer controller IAM role. | `bool` | `true` | no |
| <a name="input_eks_enable_custom_networking"></a> [eks\_enable\_custom\_networking](#input\_eks\_enable\_custom\_networking) | Enables custom networking for the EKS VPC CNI. When true, custom networking is enabled with `ENI_CONFIG_LABEL_DEF` = `topology.kubernetes.io/zone` and ENIConfig resources must be created. | `bool` | `false` | no |
| <a name="input_eks_enable_externalsnat"></a> [eks\_enable\_externalsnat](#input\_eks\_enable\_externalsnat) | Enables [External SNAT](https://docs.aws.amazon.com/eks/latest/userguide/external-snat.html) for the EKS VPC CNI. When true, the EKS pods must have a route to a NAT Gateway for outbound communication. | `bool` | `false` | no |
| <a name="input_eks_enable_fargate"></a> [eks\_enable\_fargate](#input\_eks\_enable\_fargate) | Enables Fargate profiles for the karpenter and kube-system namespaces. | `bool` | `false` | no |
| <a name="input_eks_node_additional_security_group_ids"></a> [eks\_node\_additional\_security\_group\_ids](#input\_eks\_node\_additional\_security\_group\_ids) | Additional security group ids to attach to EKS nodes. | `list(string)` | `[]` | no |
| <a name="input_eks_node_groups"></a> [eks\_node\_groups](#input\_eks\_node\_groups) | n/a | <pre>list(object({<br>    name            = string<br>    min_size        = string<br>    desired_size    = string<br>    max_size        = string<br>    volume_type     = optional(string, "gp3")<br>    disk_size       = optional(number, 200)<br>    disk_iops       = optional(number, 3000)<br>    disk_throughput = optional(number, 125)<br>    device_name     = optional(string, "/dev/xvda")<br>    instance_types  = list(string)<br>    capacity_type   = optional(string, "ON_DEMAND")<br>    labels          = optional(map(string), {})<br>    taints          = optional(map(object({ key = string, value = string, effect = string })), {})<br>  }))</pre> | <pre>[<br>  {<br>    "desired_size": 3,<br>    "instance_types": [<br>      "c5.4xlarge"<br>    ],<br>    "max_size": 9,<br>    "min_size": 3,<br>    "name": "ast-app"<br>  },<br>  {<br>    "desired_size": 0,<br>    "instance_types": [<br>      "m5.2xlarge"<br>    ],<br>    "labels": {<br>      "sast-engine": "true"<br>    },<br>    "max_size": 100,<br>    "min_size": 0,<br>    "name": "sast-engine",<br>    "taints": {<br>      "dedicated": {<br>        "effect": "NO_SCHEDULE",<br>        "key": "sast-engine",<br>        "value": "true"<br>      }<br>    }<br>  },<br>  {<br>    "desired_size": 0,<br>    "instance_types": [<br>      "m5.4xlarge"<br>    ],<br>    "labels": {<br>      "sast-engine-large": "true"<br>    },<br>    "max_size": 100,<br>    "min_size": 0,<br>    "name": "sast-engine-large",<br>    "taints": {<br>      "dedicated": {<br>        "effect": "NO_SCHEDULE",<br>        "key": "sast-engine-large",<br>        "value": "true"<br>      }<br>    }<br>  },<br>  {<br>    "desired_size": 0,<br>    "instance_types": [<br>      "r5.2xlarge"<br>    ],<br>    "labels": {<br>      "sast-engine-extra-large": "true"<br>    },<br>    "max_size": 100,<br>    "min_size": 0,<br>    "name": "sast-engine-extra-large",<br>    "taints": {<br>      "dedicated": {<br>        "effect": "NO_SCHEDULE",<br>        "key": "sast-engine-extra-large",<br>        "value": "true"<br>      }<br>    }<br>  },<br>  {<br>    "desired_size": 0,<br>    "instance_types": [<br>      "r5.4xlarge"<br>    ],<br>    "labels": {<br>      "sast-engine-xxl": "true"<br>    },<br>    "max_size": 100,<br>    "min_size": 0,<br>    "name": "sast-engine-xxl",<br>    "taints": {<br>      "dedicated": {<br>        "effect": "NO_SCHEDULE",<br>        "key": "sast-engine-xxl",<br>        "value": "true"<br>      }<br>    }<br>  },<br>  {<br>    "desired_size": 1,<br>    "instance_types": [<br>      "c5.2xlarge"<br>    ],<br>    "labels": {<br>      "kics-engine": "true"<br>    },<br>    "max_size": 100,<br>    "min_size": 1,<br>    "name": "kics-engine",<br>    "taints": {<br>      "dedicated": {<br>        "effect": "NO_SCHEDULE",<br>        "key": "kics-engine",<br>        "value": "true"<br>      }<br>    }<br>  },<br>  {<br>    "desired_size": 1,<br>    "instance_types": [<br>      "c5.2xlarge"<br>    ],<br>    "labels": {<br>      "repostore": "true"<br>    },<br>    "max_size": 100,<br>    "min_size": 1,<br>    "name": "repostore",<br>    "taints": {<br>      "dedicated": {<br>        "effect": "NO_SCHEDULE",<br>        "key": "repostore",<br>        "value": "true"<br>      }<br>    }<br>  },<br>  {<br>    "desired_size": 1,<br>    "instance_types": [<br>      "m5.2xlarge"<br>    ],<br>    "labels": {<br>      "service": "sca-source-resolver"<br>    },<br>    "max_size": 100,<br>    "min_size": 1,<br>    "name": "sca-source-resolver",<br>    "taints": {<br>      "dedicated": {<br>        "effect": "NO_SCHEDULE",<br>        "key": "service",<br>        "value": "sca-source-resolver"<br>      }<br>    }<br>  }<br>]</pre> | no |
| <a name="input_eks_pod_subnets"></a> [eks\_pod\_subnets](#input\_eks\_pod\_subnets) | The subnets to use for EKS pods. When specified, custom networking configuration is applied to the EKS cluster. | `list(string)` | n/a | yes |
| <a name="input_eks_post_bootstrap_user_data"></a> [eks\_post\_bootstrap\_user\_data](#input\_eks\_post\_bootstrap\_user\_data) | User data to insert after bootstrapping script. | `string` | `""` | no |
| <a name="input_eks_pre_bootstrap_user_data"></a> [eks\_pre\_bootstrap\_user\_data](#input\_eks\_pre\_bootstrap\_user\_data) | User data to insert before bootstrapping script. | `string` | `""` | no |
| <a name="input_eks_private_endpoint_enabled"></a> [eks\_private\_endpoint\_enabled](#input\_eks\_private\_endpoint\_enabled) | Enables the EKS VPC private endpoint. | `bool` | `true` | no |
| <a name="input_eks_public_endpoint_enabled"></a> [eks\_public\_endpoint\_enabled](#input\_eks\_public\_endpoint\_enabled) | Enables the EKS public endpoint. | `bool` | `false` | no |
| <a name="input_eks_subnets"></a> [eks\_subnets](#input\_eks\_subnets) | The subnets to deploy EKS into. | `list(string)` | n/a | yes |
| <a name="input_eks_version"></a> [eks\_version](#input\_eks\_version) | The version of the EKS Cluster (e.g. 1.27) | `string` | n/a | yes |
| <a name="input_enable_cluster_creator_admin_permissions"></a> [enable\_cluster\_creator\_admin\_permissions](#input\_enable\_cluster\_creator\_admin\_permissions) | Enables the identity used to create the EKS cluster to have administrator access to that EKS cluster. When enabled, do not specify the same principal arn for eks\_administrator\_principals. | `bool` | `true` | no |
| <a name="input_es_create"></a> [es\_create](#input\_es\_create) | Enables creation of elasticsearch resources. | `bool` | `true` | no |
| <a name="input_es_instance_count"></a> [es\_instance\_count](#input\_es\_instance\_count) | The number of nodes in elasticsearch cluster | `number` | `2` | no |
| <a name="input_es_instance_type"></a> [es\_instance\_type](#input\_es\_instance\_type) | The instance type for elasticsearch nodes. | `string` | `"r6g.large.elasticsearch"` | no |
| <a name="input_es_password"></a> [es\_password](#input\_es\_password) | The password for the elasticsearch user | `string` | n/a | yes |
| <a name="input_es_subnets"></a> [es\_subnets](#input\_es\_subnets) | The subnets to deploy Elasticsearch into. | `list(string)` | n/a | yes |
| <a name="input_es_tls_security_policy"></a> [es\_tls\_security\_policy](#input\_es\_tls\_security\_policy) | n/a | `string` | `"Policy-Min-TLS-1-2-2019-07"` | no |
| <a name="input_es_username"></a> [es\_username](#input\_es\_username) | The username for the elasticsearch user | `string` | `"ast"` | no |
| <a name="input_es_volume_size"></a> [es\_volume\_size](#input\_es\_volume\_size) | The size of volumes for nodes in elasticsearch cluster | `number` | `100` | no |
| <a name="input_kms_key_arn"></a> [kms\_key\_arn](#input\_kms\_key\_arn) | The ARN of the KMS key to use for encryption in AWS services | `string` | n/a | yes |
| <a name="input_kube_proxy_version"></a> [kube\_proxy\_version](#input\_kube\_proxy\_version) | The version of the EKS Kube Proxy Addon. | `string` | n/a | yes |
| <a name="input_launch_template_tags"></a> [launch\_template\_tags](#input\_launch\_template\_tags) | Tags to associate with launch templates for node groups | `map(string)` | `null` | no |
| <a name="input_s3_allowed_origins"></a> [s3\_allowed\_origins](#input\_s3\_allowed\_origins) | The allowed orgins for S3 CORS rules. | `list(string)` | n/a | yes |
| <a name="input_s3_retention_period"></a> [s3\_retention\_period](#input\_s3\_retention\_period) | The retention period, in days, to retain s3 objects. | `string` | `"90"` | no |
| <a name="input_vpc_cni_version"></a> [vpc\_cni\_version](#input\_vpc\_cni\_version) | The version of the EKS VPC CNI Addon. | `string` | n/a | yes |
| <a name="input_vpc_id"></a> [vpc\_id](#input\_vpc\_id) | The id of the vpc deploying into. | `string` | n/a | yes |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_analytics_db_database_name"></a> [analytics\_db\_database\_name](#output\_analytics\_db\_database\_name) | n/a |
| <a name="output_analytics_db_endpoint"></a> [analytics\_db\_endpoint](#output\_analytics\_db\_endpoint) | n/a |
| <a name="output_analytics_db_master_password"></a> [analytics\_db\_master\_password](#output\_analytics\_db\_master\_password) | n/a |
| <a name="output_analytics_db_master_username"></a> [analytics\_db\_master\_username](#output\_analytics\_db\_master\_username) | n/a |
| <a name="output_analytics_db_port"></a> [analytics\_db\_port](#output\_analytics\_db\_port) | n/a |
| <a name="output_analytics_db_reader_endpoint"></a> [analytics\_db\_reader\_endpoint](#output\_analytics\_db\_reader\_endpoint) | n/a |
| <a name="output_bucket_suffix"></a> [bucket\_suffix](#output\_bucket\_suffix) | n/a |
| <a name="output_cluster_autoscaler_iam_role_arn"></a> [cluster\_autoscaler\_iam\_role\_arn](#output\_cluster\_autoscaler\_iam\_role\_arn) | n/a |
| <a name="output_cluster_certificate_authority_data"></a> [cluster\_certificate\_authority\_data](#output\_cluster\_certificate\_authority\_data) | n/a |
| <a name="output_cluster_endpoint"></a> [cluster\_endpoint](#output\_cluster\_endpoint) | n/a |
| <a name="output_cluster_name"></a> [cluster\_name](#output\_cluster\_name) | n/a |
| <a name="output_db_database_name"></a> [db\_database\_name](#output\_db\_database\_name) | n/a |
| <a name="output_db_endpoint"></a> [db\_endpoint](#output\_db\_endpoint) | n/a |
| <a name="output_db_master_password"></a> [db\_master\_password](#output\_db\_master\_password) | n/a |
| <a name="output_db_master_username"></a> [db\_master\_username](#output\_db\_master\_username) | n/a |
| <a name="output_db_port"></a> [db\_port](#output\_db\_port) | n/a |
| <a name="output_db_reader_endpoint"></a> [db\_reader\_endpoint](#output\_db\_reader\_endpoint) | n/a |
| <a name="output_ec_endpoint"></a> [ec\_endpoint](#output\_ec\_endpoint) | n/a |
| <a name="output_ec_port"></a> [ec\_port](#output\_ec\_port) | n/a |
| <a name="output_eks"></a> [eks](#output\_eks) | n/a |
| <a name="output_es_endpoint"></a> [es\_endpoint](#output\_es\_endpoint) | n/a |
| <a name="output_es_password"></a> [es\_password](#output\_es\_password) | n/a |
| <a name="output_es_username"></a> [es\_username](#output\_es\_username) | n/a |
| <a name="output_external_dns_iam_role_arn"></a> [external\_dns\_iam\_role\_arn](#output\_external\_dns\_iam\_role\_arn) | n/a |
| <a name="output_karpenter_iam_role_arn"></a> [karpenter\_iam\_role\_arn](#output\_karpenter\_iam\_role\_arn) | n/a |
| <a name="output_load_balancer_controller_iam_role_arn"></a> [load\_balancer\_controller\_iam\_role\_arn](#output\_load\_balancer\_controller\_iam\_role\_arn) | n/a |
| <a name="output_nodegroup_iam_role_name"></a> [nodegroup\_iam\_role\_name](#output\_nodegroup\_iam\_role\_name) | n/a |
| <a name="output_s3_bucket_name_suffix"></a> [s3\_bucket\_name\_suffix](#output\_s3\_bucket\_name\_suffix) | n/a |
# Regional Considerations

## GovCloud

* RDS Proxy is not available in AWS Gov Cloud regions, so `create_rds_proxy` must be set `false`. Monitor database for connection usage and scale accordingly.
* RDS's `ManageMasterUserPassword` capability is not supported. Specify a password via `db_master_user_password`
* Elasticache's `cache.r7g` and `cache.tg4` instance class is not available. Consider using `cache.r6g` and `cache.t3`
