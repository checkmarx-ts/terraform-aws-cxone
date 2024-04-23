# Look up the database password from secrets manager, as the Kots configuration requires it.
# data "aws_secretsmanager_secret" "rds_secret" {
#   arn = var.postgres_password_secret_arn
# }
# data "aws_secretsmanager_secret_version" "rds_secret" {
#   secret_id = data.aws_secretsmanager_secret.rds_secret.id
# }

resource "local_file" "kots_config" {
  content = templatefile("${path.module}/kots.config.aws.reference.yaml.tftpl", {
    aws_region     = var.region
    admin_email    = var.admin_email
    admin_username = "admin"
    admin_password = var.admin_password

    ms_replica_count = var.ms_replica_count

    fqdn            = var.fqdn
    nlb_tls_acm_arn = var.acm_certificate_arn

    # S3 buckets
    bucket_name_suffix        = var.bucket_suffix
    deployment_id             = var.deployment_id
    object_storage_url        = var.object_storage_endpoint
    object_storage_access_key = var.object_storage_access_key
    object_storage_secret_key = var.object_storage_secret_key

    # RDS
    postgres_host     = var.postgres_host
    postgres_user     = var.postgres_user
    postgres_password = var.postgres_password #jsondecode(data.aws_secretsmanager_secret_version.rds_secret.secret_string)["password"]
    postgres_db       = var.postgres_database_name

    # Redis
    redis_address = var.redis_address

    # SMTP
    smtp_host        = var.smtp_host
    smtp_port        = var.smtp_port
    smtp_user        = var.smtp_user
    smtp_password    = var.smtp_password
    smtp_from_sender = var.smtp_from_sender

    # Elasticsearch
    elasticsearch_host     = var.elasticsearch_host
    elasticsearch_password = var.elasticsearch_password
  })
  filename = "kots.${var.deployment_id}.yaml"
}


resource "local_file" "makefile" {
  content = templatefile("${path.module}/Makefile.tftpl", {
    tf_deployment_id                      = var.deployment_id
    tf_deploy_region                      = var.region
    tf_eks_cluster_name                   = var.deployment_id
    tf_fqdn                               = var.fqdn
    tf_cxone_version                      = var.cxone_version
    tf_release_channel                    = var.release_channel
    tf_kots_password                      = var.kots_admin_password
    tf_namespace                          = "ast"
    tf_license_file                       = var.license_file
    tf_kots_config_file                   = "kots.${var.deployment_id}.yaml"
    namespace                             = "ast"
    kots_config_file                      = "kots.${var.deployment_id}.yaml"
    license_file                          = var.license_file
    release_channel                       = var.release_channel
    app_version                           = var.cxone_version
    cluster_autoscaler_iam_role_arn       = var.cluster_autoscaler_iam_role_arn
    load_balancer_controller_iam_role_arn = var.load_balancer_controller_iam_role_arn
    external_dns_iam_role_arn             = var.external_dns_iam_role_arn
    karpenter_iam_role_arn                = var.karpenter_iam_role_arn
    cluster_endpoint                      = var.cluster_endpoint
    vpc_id                                = var.vpc_id
  })
  filename = "Makefile"
}

resource "local_file" "karpenter" {
  content = templatefile("${path.module}/karpenter.reference.yaml.tftpl", {
    deployment_id           = var.deployment_id
    nodegroup_iam_role_name = var.nodegroup_iam_role_name
    availability_zones      = jsonencode(var.availability_zones)

  })
  filename = "karpenter.${var.deployment_id}.yaml"
}

resource "local_file" "storage_class" {
  content = templatefile("${path.module}/apply-storageclass-config.sh.tftpl", {
    deployment_id           = var.deployment_id
    nodegroup_iam_role_name = var.nodegroup_iam_role_name
    availability_zones      = jsonencode(var.availability_zones)
    karpenter_iam_role_arn  = var.karpenter_iam_role_arn

  })
  filename = "apply-storageclass-config.${var.deployment_id}.sh"
}

resource "local_file" "ENIConfig" {
  content  = var.pod_eniconfig
  filename = "custom-networking-config.${var.deployment_id}.yaml"
}
