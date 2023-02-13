
# METADATA
deployment_id = ""
environment   = ""
owner         = ""
aws_profile   = ""
aws_region    = ""

#VPC
vpc_cidr = ""

vpc = {
  create                    = true
  single_nat                = true
  nat_per_az                = false
  existing_vpc_id           = ""
  existing_subnet_ids       = []
  existing_db_subnets_group = ""
  existing_db_subnets       = []
}

# Security
sig = {
  create                     = true
  existing_sig_k8s_to_dbs_id = ""
}

# IAM-ROLE
iam_role = {
  cloudops_arn = true
  customer_arn = ""
}

# KMS
kms = {
  create           = true
  existing_kms_arn = ""
}

# EKS
eks_cluster_version = "1.24"

# RDS
postgres_nodes = {
  create              = true
  auto_scaling_enable = false
  count               = 1
  max_count           = 0
  instance_type       = "db.r6g.xlarge"
}

# REDIS
redis_nodes = {
  create             = true
  instance_type      = "cache.t4g.medium"
  number_of_shards   = 3
  replicas_per_shard = 1
}
