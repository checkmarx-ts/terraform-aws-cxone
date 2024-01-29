resource "random_string" "random_suffix" {
  length  = 6
  special = false
  upper   = false
}

locals {
  s3_bucket_name_suffix = "${var.deployment_id}-${random_string.random_suffix.result}"

  buckets = {

    uploads = {
      name = "uploads-${lower(local.s3_bucket_name_suffix)}"
    },
    queries = {
      name = "queries-${lower(local.s3_bucket_name_suffix)}"
    },
    misc = {
      name = "misc-${lower(local.s3_bucket_name_suffix)}"
    },
    repostore = {
      name = "repostore-${lower(local.s3_bucket_name_suffix)}"
    },
    sast_metadata = {
      name = "sast-metadata-${lower(local.s3_bucket_name_suffix)}"
    },
    scans = {
      name = "scans-${lower(local.s3_bucket_name_suffix)}"
    },
    sast_worker = {
      name = "sast-worker-${lower(local.s3_bucket_name_suffix)}"
    }
    kics_worker = {
      name = "kics-worker-${lower(local.s3_bucket_name_suffix)}"
    }
    sca_worker = {
      name = "sca-worker-${lower(local.s3_bucket_name_suffix)}"
    }
    logs = {
      name = "logs-${lower(local.s3_bucket_name_suffix)}"
    }
    engine_logs = {
      name = "engine-logs-${lower(local.s3_bucket_name_suffix)}"
    }
    reports = {
      name = "reports-${lower(local.s3_bucket_name_suffix)}"
    }
    report_templates = {
      name = "report-templates-${lower(local.s3_bucket_name_suffix)}"
    }
    configuration = {
      name = "configuration-${lower(local.s3_bucket_name_suffix)}"
    }
    imports = {
      name = "imports-${lower(local.s3_bucket_name_suffix)}"
    }
    audit = {
      name = "audit-${lower(local.s3_bucket_name_suffix)}"
    }
    source_resolver = {
      name = "source-resolver-${lower(local.s3_bucket_name_suffix)}"
    }
    api_security = {
      name = "apisec-${lower(local.s3_bucket_name_suffix)}"
    }
    redis = {
      name = "redis-shared-bucket-${lower(local.s3_bucket_name_suffix)}"
    }
    scan_results_storage = {
      name = "scan-results-storage-${lower(local.s3_bucket_name_suffix)}"
    }
    export = {
      name = "export-${lower(local.s3_bucket_name_suffix)}"
    }
    cxone = {
      name = "cxone-${lower(local.s3_bucket_name_suffix)}"
    }
  }
}



module "s3_bucket" {
  for_each = local.buckets
  source   = "terraform-aws-modules/s3-bucket/aws"

  bucket           = each.value.name
  force_destroy    = true
  object_ownership = "BucketOwnerPreferred"
  acl              = "private"
  versioning = {
    enabled = true
  }
  server_side_encryption_configuration = {
    rule = {
      apply_server_side_encryption_by_default = {
        sse_algorithm = "AES256"
      }
    }

  }
  lifecycle_rule = [
    {
      id     = "Transition-To-Intelligent-Tiering"
      status = "Enabled"
      # abort_incomplete_multipart_upload_days = 1 (not expected here)
      transition = {
        days          = 0
        storage_class = "INTELLIGENT_TIERING"
      }
    },
    {
      id     = "${var.s3_retention_period}-Days-Non-Current-Expiration"
      status = "Enabled"
      noncurrent_version_expiration = {
        noncurrent_days = var.s3_retention_period
      }
      expiration = {
        expired_object_delete_marker = true
      }
    }
  ]

  control_object_ownership              = true
  block_public_acls                     = true
  block_public_policy                   = true
  ignore_public_acls                    = true
  restrict_public_buckets               = true
  attach_deny_insecure_transport_policy = true

  tags = {
    Name        = "${var.deployment_id} misc bucket"
    Environment = "${var.deployment_id}"
  }
}