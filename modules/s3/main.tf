resource "random_string" "random_suffix" {
  length  = 6
  special = false
  upper   = false
}

locals {
  s3_bucket_name_suffix = "${var.deployment_id}-${random_string.random_suffix.result}"

  buckets = {
    api_security = {
      name        = "apisec"
      enable_cors = false
    }
    audit = {
      name        = "audit"
      enable_cors = false
    }
    configuration = {
      name        = "configuration"
      enable_cors = false
    }
    cxone = {
      name        = "cxone"
      enable_cors = false
    }
    engine_logs = {
      name        = "engine-logs"
      enable_cors = false
    }
    export = {
      name        = "export"
      enable_cors = false
    }
    imports = {
      name        = "imports"
      enable_cors = false
    }
    kics_worker = {
      name        = "kics-worker"
      enable_cors = false
    }
    logs = {
      name        = "logs"
      enable_cors = true
    }
    misc = {
      name        = "misc"
      enable_cors = false
    }
    queries = {
      name        = "queries"
      enable_cors = false
    }
    redis = {
      name        = "redis-shared-bucket"
      enable_cors = false
    }
    reports = {
      name        = "reports"
      enable_cors = true
    }
    report_templates = {
      name        = "report-templates"
      enable_cors = false
    }
    repostore = {
      name        = "repostore"
      enable_cors = true
    }
    sast_metadata = {
      name        = "sast-metadata"
      enable_cors = false
    }
    sast_worker = {
      name        = "sast-worker"
      enable_cors = false
    }
    scan_results_storage = {
      name        = "scan-results-storage"
      enable_cors = true
    }
    scans = {
      name        = "scans"
      enable_cors = false
    }
    sca_worker = {
      name        = "sca-worker"
      enable_cors = false
    }
    source_resolver = {
      name        = "source-resolver"
      enable_cors = false
    }
    uploads = {
      name        = "uploads"
      enable_cors = true
    }
  }
}


module "s3_bucket" {
  for_each = local.buckets
  source   = "terraform-aws-modules/s3-bucket/aws"

  bucket           = "${each.value.name}-${lower(local.s3_bucket_name_suffix)}"
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

  cors_rule = each.value.enable_cors != true ? [] : [
    {
      allowed_headers = ["*"]
      allowed_methods = ["GET", "PUT", "POST", "HEAD"]
      allowed_origins = var.s3_cors_allowed_origins
    }
  ]

  control_object_ownership              = true
  block_public_acls                     = true
  block_public_policy                   = true
  ignore_public_acls                    = true
  restrict_public_buckets               = true
  attach_deny_insecure_transport_policy = true
}
