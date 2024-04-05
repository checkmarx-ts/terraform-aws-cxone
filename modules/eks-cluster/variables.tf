
variable "deployment_id" {
  description = "The id of the deployment. Will be used to name resources like EKS cluster, etc."
  type        = string
  nullable    = false
  validation {
    condition     = (length(var.deployment_id) > 0)
    error_message = "The deployment_id is required."
  }
}

variable "vpc_id" {
  type        = string
  nullable    = false
  description = "The VPC ID to deploy into."
}

variable "subnet_ids" {
  type        = list(string)
  nullable    = false
  description = "The subnet_ids to deploy into."
}

variable "enable_private_endpoint" {
  type    = bool
  default = true
}

variable "enable_public_endpoint" {
  type    = bool
  default = true
}

variable "eks_cluster_version" {
  description = "EKS Kubernetes version to be used"
  type        = string
  default     = "1.27"
  nullable    = false
}

variable "eks_kms_key_arn" {
  description = "The ARN of the KMS key to use for cluster secrets encryption."
  type        = string
  nullable    = false
}

variable "cluster_security_group_id" {
  description = "Existing security group ID to be attached to the cluster."
  type        = string
}

variable "node_security_group_id" {
  description = "ID of an existing security group to attach to the node groups created."
  type        = string
}


variable "default_security_group_ids" {
  description = "A list of security group ids to add to all managed node group nodes by default."
  type        = list(string)
  default     = []
}

variable "cluster_access_iam_role_arn" {
  type        = string
  nullable    = false
  description = "The role for cluster administrators."
}


variable "default_node_group" {
  type = object({
    instance_types  = list(string)
    min_size        = number
    desired_size    = number
    max_size        = number
    capacity_type   = string
    disk_size_gib   = number
    disk_iops       = number
    disk_throughput = number
    device_name     = string
    volume_type     = string
    name            = string
  })
  default = {
    name            = "ast-app"
    min_size        = 3
    desired_size    = 3
    max_size        = 10
    instance_types  = ["c5.4xlarge"]
    disk_size_gib   = 200
    disk_iops       = 3000 # this should be the default
    disk_throughput = 125  # this should be the default
    capacity_type   = "ON_DEMAND"
    device_name     = "/dev/xvda"
    volume_type     = "gp3"
  }
  validation {
    condition     = var.default_node_group.desired_size >= 1
    error_message = "You must have at least 1 instance in this node group."
  }
  validation {
    condition     = var.default_node_group.disk_size_gib >= 200
    error_message = "You must provide at least 20 GiB per node."
  }

  validation {
    condition     = alltrue([var.default_node_group.disk_iops >= 3000, var.default_node_group.disk_iops <= 16000])
    error_message = "You must provide a value between 3000 and 16000."
  }

  validation {
    condition     = alltrue([var.default_node_group.disk_throughput >= 125, var.default_node_group.disk_throughput <= 1000])
    error_message = "You must provide a value between 125 and 1000."
  }
  description = "Configuration for the AST nodes"
}


variable "sast_nodes" {
  type = object({
    instance_types  = list(string)
    min_size        = number
    desired_size    = number
    max_size        = number
    capacity_type   = string
    disk_size_gib   = number
    disk_iops       = number
    disk_throughput = number
    device_name     = string
    volume_type     = string
    key             = string
    value           = string
    effect          = string
    name            = string
    label_name      = string
    label_value     = string
  })

  default = {
    name            = "sast-engine"
    min_size        = 0
    desired_size    = 0
    max_size        = 100
    instance_types  = ["m5.2xlarge"]
    disk_size_gib   = 200
    disk_iops       = 3000 # this should be the default
    disk_throughput = 125  # this should be the default
    capacity_type   = "ON_DEMAND"
    device_name     = "/dev/xvda"
    volume_type     = "gp3"
    key             = "sast-engine"
    value           = "true"
    effect          = "NO_SCHEDULE"
    label_name      = "sast-engine"
    label_value     = "true"
  }
  validation {
    condition     = var.sast_nodes.disk_size_gib >= 200
    error_message = "You must provide at least 200 GiB per node."
  }
  validation {
    condition     = alltrue([var.sast_nodes.disk_iops >= 3000, var.sast_nodes.disk_iops <= 16000])
    error_message = "You must provide a value between 3000 and 16000."
  }

  validation {
    condition     = alltrue([var.sast_nodes.disk_throughput >= 125, var.sast_nodes.disk_throughput <= 1000])
    error_message = "You must provide a value between 125 and 1000."
  }
  description = "Configuration for the SAST nodes"
}


# -------------------
variable "sast_nodes_large" {
  type = object({
    instance_types  = list(string)
    min_size        = number
    desired_size    = number
    max_size        = number
    capacity_type   = string
    disk_size_gib   = number
    disk_iops       = number
    disk_throughput = number
    device_name     = string
    volume_type     = string
    key             = string
    value           = string
    effect          = string
    name            = string
    label_name      = string
    label_value     = string
  })

  default = {
    name            = "sast-engine-large"
    min_size        = 0
    desired_size    = 0
    max_size        = 300
    instance_types  = ["m5.4xlarge"]
    disk_size_gib   = 200
    disk_iops       = 3000 # this should be the default
    disk_throughput = 125  # this should be the default
    capacity_type   = "ON_DEMAND"
    device_name     = "/dev/xvda"
    volume_type     = "gp3"
    key             = "sast-engine-large"
    value           = "true"
    effect          = "NO_SCHEDULE"
    label_name      = "sast-engine-large"
    label_value     = "true"
  }
  validation {
    condition     = var.sast_nodes_large.disk_size_gib >= 200
    error_message = "You must provide at least 200 GiB per node."
  }
  validation {
    condition     = alltrue([var.sast_nodes_large.disk_iops >= 3000, var.sast_nodes_large.disk_iops <= 16000])
    error_message = "You must provide a value between 3000 and 16000."
  }

  validation {
    condition     = alltrue([var.sast_nodes_large.disk_throughput >= 125, var.sast_nodes_large.disk_throughput <= 1000])
    error_message = "You must provide a value between 125 and 1000."
  }
  description = "Configuration for the SAST nodes"
}

variable "sast_nodes_extra_large" {
  type = object({
    instance_types  = list(string)
    min_size        = number
    desired_size    = number
    max_size        = number
    capacity_type   = string
    disk_size_gib   = number
    disk_iops       = number
    disk_throughput = number
    device_name     = string
    volume_type     = string
    key             = string
    value           = string
    effect          = string
    name            = string
    label_name      = string
    label_value     = string
  })

  default = {
    name            = "sast-engine-extra-large"
    min_size        = 0
    desired_size    = 0
    max_size        = 100
    instance_types  = ["r5.2xlarge"]
    disk_size_gib   = 200
    disk_iops       = 3000 # this should be the default
    disk_throughput = 125  # this should be the default
    capacity_type   = "ON_DEMAND"
    device_name     = "/dev/xvda"
    volume_type     = "gp3"
    key             = "sast-engine-extra-large"
    value           = "true"
    effect          = "NO_SCHEDULE"
    label_name      = "sast-engine-extra-large"
    label_value     = "true"
  }
  validation {
    condition     = var.sast_nodes_extra_large.disk_size_gib >= 200
    error_message = "You must provide at least 200 GiB per node."
  }
  validation {
    condition     = alltrue([var.sast_nodes_extra_large.disk_iops >= 3000, var.sast_nodes_extra_large.disk_iops <= 16000])
    error_message = "You must provide a value between 3000 and 16000."
  }

  validation {
    condition     = alltrue([var.sast_nodes_extra_large.disk_throughput >= 125, var.sast_nodes_extra_large.disk_throughput <= 1000])
    error_message = "You must provide a value between 125 and 1000."
  }
  description = "Configuration for the SAST nodes"
}

variable "sast_nodes_xxl" {
  type = object({
    instance_types  = list(string)
    min_size        = number
    desired_size    = number
    max_size        = number
    capacity_type   = string
    disk_size_gib   = number
    disk_iops       = number
    disk_throughput = number
    device_name     = string
    volume_type     = string
    key             = string
    value           = string
    effect          = string
    name            = string
    label_name      = string
    label_value     = string
  })

  default = {
    name            = "sast-engine-xxl"
    min_size        = 0
    desired_size    = 0
    max_size        = 50
    instance_types  = ["r5.4xlarge"]
    disk_size_gib   = 200
    disk_iops       = 3000 # this should be the default
    disk_throughput = 125  # this should be the default
    capacity_type   = "ON_DEMAND"
    device_name     = "/dev/xvda"
    volume_type     = "gp3"
    key             = "sast-engine-xxl"
    value           = "true"
    effect          = "NO_SCHEDULE"
    label_name      = "sast-engine-xxl"
    label_value     = "true"
  }
  validation {
    condition     = var.sast_nodes_xxl.disk_size_gib >= 200
    error_message = "You must provide at least 200 GiB per node."
  }
  validation {
    condition     = alltrue([var.sast_nodes_xxl.disk_iops >= 3000, var.sast_nodes_xxl.disk_iops <= 16000])
    error_message = "You must provide a value between 3000 and 16000."
  }

  validation {
    condition     = alltrue([var.sast_nodes_xxl.disk_throughput >= 125, var.sast_nodes_xxl.disk_throughput <= 1000])
    error_message = "You must provide a value between 125 and 1000."
  }
  description = "Configuration for the SAST nodes"
}

variable "kics_nodes" {
  type = object({
    name            = string
    instance_types  = list(string)
    min_size        = number
    desired_size    = number
    max_size        = number
    capacity_type   = string
    disk_size_gib   = number
    disk_iops       = number
    disk_throughput = number
    device_name     = string
    volume_type     = string
    key             = string
    value           = string
    effect          = string
    label_name      = string
    label_value     = string
  })

  default = {
    name            = "kics-engine"
    min_size        = 1
    desired_size    = 1
    max_size        = 10
    instance_types  = ["c5.2xlarge"]
    disk_size_gib   = 200
    disk_iops       = 3000 # this should be the default
    disk_throughput = 125  # this should be the default
    capacity_type   = "ON_DEMAND"
    device_name     = "/dev/xvda"
    volume_type     = "gp3"
    key             = "kics-engine"
    value           = "true"
    effect          = "NO_SCHEDULE"
    label_name      = "kics-engine"
    label_value     = "true"
  }
  validation {
    condition     = var.kics_nodes.disk_size_gib >= 200
    error_message = "You must provide at least 200 GiB per node."
  }
  validation {
    condition     = alltrue([var.kics_nodes.disk_iops >= 3000, var.kics_nodes.disk_iops <= 16000])
    error_message = "You must provide a value between 3000 and 16000."
  }

  validation {
    condition     = alltrue([var.kics_nodes.disk_throughput >= 125, var.kics_nodes.disk_throughput <= 1000])
    error_message = "You must provide a value between 125 and 1000."
  }
  description = "Configuration for the SAST nodes"
}

# MINIO
variable "minio_gateway_nodes" {
  type = object({
    name            = string
    instance_types  = list(string)
    min_size        = number
    desired_size    = number
    max_size        = number
    capacity_type   = string
    disk_size_gib   = number
    disk_iops       = number
    disk_throughput = number
    device_name     = string
    volume_type     = string
    key             = string
    value           = string
    effect          = string
    label_name      = string
    label_value     = string
  })

  default = {
    name            = "minio-gateway"
    min_size        = 0
    desired_size    = 0
    max_size        = 10
    instance_types  = ["c6i.4xlarge"]
    disk_size_gib   = 200
    disk_iops       = 3000 # this should be the default
    disk_throughput = 125  # this should be the default
    capacity_type   = "ON_DEMAND"
    device_name     = "/dev/xvda"
    volume_type     = "gp3"
    key             = "minio-gateway"
    value           = "true"
    effect          = "NO_SCHEDULE"
    label_name      = "minio-gateway"
    label_value     = "true"
  }
  validation {
    condition     = var.minio_gateway_nodes.disk_size_gib >= 200
    error_message = "You must provide at least 200 GiB per node."
  }
  validation {
    condition     = alltrue([var.minio_gateway_nodes.disk_iops >= 3000, var.minio_gateway_nodes.disk_iops <= 16000])
    error_message = "You must provide a value between 3000 and 16000."
  }

  validation {
    condition     = alltrue([var.minio_gateway_nodes.disk_throughput >= 125, var.minio_gateway_nodes.disk_throughput <= 1000])
    error_message = "You must provide a value between 125 and 1000."
  }
  description = "Configuration for the Minio Gateway nodes"
}

# REPOSTORE
variable "repostore_nodes" {
  type = object({
    name            = string
    instance_types  = list(string)
    min_size        = number
    desired_size    = number
    max_size        = number
    capacity_type   = string
    disk_size_gib   = number
    disk_iops       = number
    disk_throughput = number
    device_name     = string
    volume_type     = string
    key             = string
    value           = string
    effect          = string
    label_name      = string
    label_value     = string
  })

  default = {
    name            = "repostore"
    min_size        = 1
    desired_size    = 1
    max_size        = 10
    instance_types  = ["c5.2xlarge"]
    disk_size_gib   = 200
    disk_iops       = 3000 # this should be the default
    disk_throughput = 125  # this should be the default
    capacity_type   = "ON_DEMAND"
    device_name     = "/dev/xvda"
    volume_type     = "gp3"
    key             = "repostore"
    value           = "true"
    effect          = "NO_SCHEDULE"
    label_name      = "repostore"
    label_value     = "true"
  }
  validation {
    condition     = var.repostore_nodes.disk_size_gib >= 200
    error_message = "You must provide at least 200 GiB per node."
  }
  validation {
    condition     = alltrue([var.repostore_nodes.disk_iops >= 3000, var.repostore_nodes.disk_iops <= 16000])
    error_message = "You must provide a value between 3000 and 16000."
  }

  validation {
    condition     = alltrue([var.repostore_nodes.disk_throughput >= 125, var.repostore_nodes.disk_throughput <= 1000])
    error_message = "You must provide a value between 125 and 1000."
  }
  description = "Configuration for the Minio Gateway nodes"
}

# SCA
variable "sca_nodes" {
  type = object({
    name            = string
    instance_types  = list(string)
    min_size        = number
    desired_size    = number
    max_size        = number
    capacity_type   = string
    disk_size_gib   = number
    disk_iops       = number
    disk_throughput = number
    device_name     = string
    volume_type     = string
    key             = string
    value           = string
    effect          = string
    label_name      = string
    label_value     = string
  })

  default = {
    name            = "sca"
    min_size        = 0
    desired_size    = 0
    max_size        = 3
    instance_types  = ["c5.2xlarge"]
    disk_size_gib   = 200
    disk_iops       = 3000 # this should be the default
    disk_throughput = 125  # this should be the default
    capacity_type   = "ON_DEMAND"
    device_name     = "/dev/xvda"
    volume_type     = "gp3"
    key             = "sca"
    value           = "true"
    effect          = "NO_SCHEDULE"
    label_name      = "sca"
    label_value     = "true"
  }
  validation {
    condition     = var.sca_nodes.disk_size_gib >= 200
    error_message = "You must provide at least 200 GiB per node."
  }
  validation {
    condition     = alltrue([var.sca_nodes.disk_iops >= 3000, var.sca_nodes.disk_iops <= 16000])
    error_message = "You must provide a value between 3000 and 16000."
  }

  validation {
    condition     = alltrue([var.sca_nodes.disk_throughput >= 125, var.sca_nodes.disk_throughput <= 1000])
    error_message = "You must provide a value between 125 and 1000."
  }
  description = "Configuration for the SCA nodes"
}

variable "sca_source_resolver_nodes" {
  type = object({
    name            = string
    instance_types  = list(string)
    min_size        = number
    desired_size    = number
    max_size        = number
    capacity_type   = string
    disk_size_gib   = number
    disk_iops       = number
    disk_throughput = number
    device_name     = string
    volume_type     = string
    key             = string
    value           = string
    effect          = string
    label_name      = string
    label_value     = string
  })

  default = {
    name            = "sca-source-resolver"
    min_size        = 0
    desired_size    = 0
    max_size        = 3
    instance_types  = ["m5.2xlarge"]
    disk_size_gib   = 200
    disk_iops       = 3000 # this should be the default
    disk_throughput = 125  # this should be the default
    capacity_type   = "ON_DEMAND"
    device_name     = "/dev/xvda"
    volume_type     = "gp3"
    key             = "service"
    value           = "sca-source-resolver"
    effect          = "NO_SCHEDULE"
    label_name      = "service"
    label_value     = "sca-source-resolver"
  }
  validation {
    condition     = var.sca_source_resolver_nodes.disk_size_gib >= 200
    error_message = "You must provide at least 200 GiB per node."
  }
  validation {
    condition     = alltrue([var.sca_source_resolver_nodes.disk_iops >= 3000, var.sca_source_resolver_nodes.disk_iops <= 16000])
    error_message = "You must provide a value between 3000 and 16000."
  }

  validation {
    condition     = alltrue([var.sca_source_resolver_nodes.disk_throughput >= 125, var.sca_source_resolver_nodes.disk_throughput <= 1000])
    error_message = "You must provide a value between 125 and 1000."
  }
  description = "Configuration for the SCA nodes"
}



# METRICS
variable "metrics_nodes" {
  type = object({
    name            = string
    instance_types  = list(string)
    min_size        = number
    desired_size    = number
    max_size        = number
    capacity_type   = string
    disk_size_gib   = number
    disk_iops       = number
    disk_throughput = number
    device_name     = string
    volume_type     = string
    key             = string
    value           = string
    effect          = string
    label_name      = string
    label_value     = string
  })

  default = {
    name            = "metrics"
    min_size        = 1
    desired_size    = 1
    max_size        = 4
    instance_types  = ["c5.xlarge"]
    disk_size_gib   = 200
    disk_iops       = 3000 # this should be the default
    disk_throughput = 125  # this should be the default
    capacity_type   = "ON_DEMAND"
    device_name     = "/dev/xvda"
    volume_type     = "gp3"
    key             = "metrics"
    value           = "true"
    effect          = "NO_SCHEDULE"
    label_name      = "metrics"
    label_value     = "true"
  }
  validation {
    condition     = var.metrics_nodes.disk_size_gib >= 200
    error_message = "You must provide at least 200 GiB per node."
  }
  validation {
    condition     = alltrue([var.metrics_nodes.disk_iops >= 3000, var.metrics_nodes.disk_iops <= 16000])
    error_message = "You must provide a value between 3000 and 16000."
  }

  validation {
    condition     = alltrue([var.metrics_nodes.disk_throughput >= 125, var.metrics_nodes.disk_throughput <= 1000])
    error_message = "You must provide a value between 125 and 1000."
  }
  description = "Configuration for the Metrics nodes"
}

# REPORTS
variable "reports_nodes" {
  type = object({
    name            = string
    instance_types  = list(string)
    min_size        = number
    desired_size    = number
    max_size        = number
    capacity_type   = string
    disk_size_gib   = number
    disk_iops       = number
    disk_throughput = number
    device_name     = string
    volume_type     = string
    key             = string
    value           = string
    effect          = string
    label_name      = string
    label_value     = string
  })

  default = {
    name            = "reports"
    min_size        = 0
    desired_size    = 1
    max_size        = 4
    instance_types  = ["m5.xlarge"]
    disk_size_gib   = 200
    disk_iops       = 3000 # this should be the default
    disk_throughput = 125  # this should be the default
    capacity_type   = "ON_DEMAND"
    device_name     = "/dev/xvda"
    volume_type     = "gp3"
    key             = "reports"
    value           = "true"
    effect          = "NO_SCHEDULE"
    label_name      = "reports"
    label_value     = "true"
  }
  validation {
    condition     = var.reports_nodes.disk_size_gib >= 200
    error_message = "You must provide at least 200 GiB per node."
  }
  validation {
    condition     = alltrue([var.reports_nodes.disk_iops >= 3000, var.reports_nodes.disk_iops <= 16000])
    error_message = "You must provide a value between 3000 and 16000."
  }

  validation {
    condition     = alltrue([var.reports_nodes.disk_throughput >= 125, var.reports_nodes.disk_throughput <= 1000])
    error_message = "You must provide a value between 125 and 1000."
  }
  description = "Configuration for the Reports nodes"
}

# DAST
variable "dast_nodes" {
  type = object({
    name            = string
    instance_types  = list(string)
    min_size        = number
    desired_size    = number
    max_size        = number
    capacity_type   = string
    disk_size_gib   = number
    disk_iops       = number
    disk_throughput = number
    device_name     = string
    volume_type     = string
    key             = string
    value           = string
    effect          = string
    label_name      = string
    label_value     = string
  })

  default = {
    name            = "dast"
    min_size        = 1
    desired_size    = 1
    max_size        = 10
    instance_types  = ["m5.xlarge"]
    disk_size_gib   = 200
    disk_iops       = 3000 # this should be the default
    disk_throughput = 125  # this should be the default
    capacity_type   = "ON_DEMAND"
    device_name     = "/dev/xvda"
    volume_type     = "gp3"
    key             = "dast"
    value           = "true"
    effect          = "NO_SCHEDULE"
    label_name      = "dast"
    label_value     = "true"
  }
  validation {
    condition     = var.dast_nodes.disk_size_gib >= 200
    error_message = "You must provide at least 200 GiB per node."
  }
  validation {
    condition     = alltrue([var.dast_nodes.disk_iops >= 3000, var.dast_nodes.disk_iops <= 16000])
    error_message = "You must provide a value between 3000 and 16000."
  }

  validation {
    condition     = alltrue([var.dast_nodes.disk_throughput >= 125, var.dast_nodes.disk_throughput <= 1000])
    error_message = "You must provide a value between 125 and 1000."
  }
  description = "Configuration for the Dast nodes"
}


variable "nodegroup_iam_role_arn" {
  description = "The ARN to the IAM role for the EKS nodes."
  nullable    = false
}

variable "launch_template_tags" {
  type        = map(string)
  description = "Tags to associate with launch templates for node groups"
  default     = null
}

variable "additional_node_security_group_ids" {
  type        = list(string)
  description = "Additional security group ids to add to node group instances."
  default     = []
}

variable "ec2_key_name" {
  type        = string
  description = "The keyname that should be used for the instances."
  default     = null
}

variable "pod_custom_networking_subnets" {
  type = list(object({
    availability_zone = string
    subnet_id         = string
  }))
  description = "A list of subnet ids and availability zones for deploying pods into with custom networking."
  default     = null
}

