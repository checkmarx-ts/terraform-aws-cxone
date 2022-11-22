locals {
  deployment_id = var.deployment_id

  #ast-default
  cluster_autoscaler_ast_default_asg_tags = [
    {
      tagKey   = "k8s.io/cluster-autoscaler/enabled"
      tagValue = "true"
    },
    {
      tagKey   = "k8s.io/cluster-autoscaler/${var.deployment_id}"
      tagValue = "owned"
    },
  ]

  #ast_sast_engines
  cluster_autoscaler_ast_sast_engines_asg_tags = [
    {
      tagKey   = "k8s.io/cluster-autoscaler/enabled"
      tagValue = "true"
    },
    {
      tagKey   = "k8s.io/cluster-autoscaler/node-template/label/${var.sast_nodes.label_name}"
      tagValue = var.sast_nodes.label_value
    },
    {
      tagKey   = "k8s.io/cluster-autoscaler/node-template/taint/${var.sast_nodes.key}"
      tagValue = "${var.sast_nodes.value}:${var.sast_nodes_large.effect}"
    },
    {
      tagKey   = "k8s.io/cluster-autoscaler/${var.deployment_id}"
      tagValue = "owned"
    },
  ]

  #sast_nodes_medium
  cluster_autoscaler_ast_sast_medium_engines_asg_tags = [
    {
      tagKey   = "k8s.io/cluster-autoscaler/enabled"
      tagValue = "true"
    },
    {
      tagKey   = "k8s.io/cluster-autoscaler/node-template/label/${var.sast_nodes_medium.label_name}"
      tagValue = var.sast_nodes_medium.label_value
    },
    {
      tagKey   = "k8s.io/cluster-autoscaler/node-template/taint/${var.sast_nodes_medium.key}"
      tagValue = "${var.sast_nodes_medium.value}:${var.sast_nodes_medium.effect}"
    },
    {
      tagKey   = "k8s.io/cluster-autoscaler/${var.deployment_id}"
      tagValue = "owned"
    },
  ]

  #sast_nodes_large
  cluster_autoscaler_ast_sast_large_engines_asg_tags = [
    {
      tagKey   = "k8s.io/cluster-autoscaler/enabled"
      tagValue = "true"
    },
    {
      tagKey   = "k8s.io/cluster-autoscaler/node-template/label/${var.sast_nodes_large.label_name}"
      tagValue = var.sast_nodes_large.label_value
    },
    {
      tagKey   = "k8s.io/cluster-autoscaler/node-template/taint/${var.sast_nodes_large.key}"
      tagValue = "${var.sast_nodes_large.value}:${var.sast_nodes_large.effect}"
    },
    {
      tagKey   = "k8s.io/cluster-autoscaler/${var.deployment_id}"
      tagValue = "owned"
    },
  ]

  #sast_nodes_extra_large
  cluster_autoscaler_ast_sast_extra_large_engines_asg_tags = [
    {
      tagKey   = "k8s.io/cluster-autoscaler/enabled"
      tagValue = "true"
    },
    {
      tagKey   = "k8s.io/cluster-autoscaler/node-template/label/${var.sast_nodes_extra_large.label_name}"
      tagValue = var.sast_nodes_extra_large.label_value
    },
    {
      tagKey   = "k8s.io/cluster-autoscaler/node-template/taint/${var.sast_nodes_extra_large.key}"
      tagValue = "${var.sast_nodes_extra_large.value}:${var.sast_nodes_extra_large.effect}"
    },
    {
      tagKey   = "k8s.io/cluster-autoscaler/${var.deployment_id}"
      tagValue = "owned"
    },
  ]

  #sast_nodes_xxl
  cluster_autoscaler_ast_sast_xxl_engines_asg_tags = [
    {
      tagKey   = "k8s.io/cluster-autoscaler/enabled"
      tagValue = "true"
    },
    {
      tagKey   = "k8s.io/cluster-autoscaler/node-template/label/${var.sast_nodes_xxl.label_name}"
      tagValue = var.sast_nodes_xxl.label_value
    },
    {
      tagKey   = "k8s.io/cluster-autoscaler/node-template/taint/${var.sast_nodes_xxl.key}"
      tagValue = "${var.sast_nodes_xxl.value}:${var.sast_nodes_xxl.effect}"
    },
    {
      tagKey   = "k8s.io/cluster-autoscaler/${var.deployment_id}"
      tagValue = "owned"
    },
  ]

  #Kics
  cluster_autoscaler_kics_nodes_engines_asg_tags = [
    {
      tagKey   = "k8s.io/cluster-autoscaler/enabled"
      tagValue = "true"
    },
    {
      tagKey   = "k8s.io/cluster-autoscaler/node-template/label/${var.kics_nodes.label_name}"
      tagValue = var.kics_nodes.label_value
    },
    {
      tagKey   = "k8s.io/cluster-autoscaler/node-template/taint/${var.kics_nodes.key}"
      tagValue = "${var.kics_nodes.value}:${var.kics_nodes.effect}"
    },
    {
      tagKey   = "k8s.io/cluster-autoscaler/${var.deployment_id}"
      tagValue = "owned"
    },
  ]

  # MINIO
  cluster_autoscaler_minio_gateway_nodes_asg_tags = [
    {
      tagKey   = "k8s.io/cluster-autoscaler/enabled"
      tagValue = "true"
    },
    {
      tagKey   = "k8s.io/cluster-autoscaler/node-template/label/${var.minio_gateway_nodes.label_name}"
      tagValue = var.minio_gateway_nodes.label_value
    },
    {
      tagKey   = "k8s.io/cluster-autoscaler/node-template/taint/${var.minio_gateway_nodes.key}"
      tagValue = "${var.minio_gateway_nodes.value}:${var.minio_gateway_nodes.effect}"
    },
    {
      tagKey   = "k8s.io/cluster-autoscaler/${var.deployment_id}"
      tagValue = "owned"
    },
  ]

  private_subnets  = slice(cidrsubnets(var.vpc_cidr, 2, 2, 2, 5, 5, 5, 6, 6, 6), 0, 3)
  public_subnets   = slice(cidrsubnets(var.vpc_cidr, 2, 2, 2, 5, 5, 5, 6, 6, 6), 6, 9)
  database_subnets = slice(cidrsubnets(var.vpc_cidr, 2, 2, 2, 5, 5, 5, 6, 6, 6), 3, 6)

}