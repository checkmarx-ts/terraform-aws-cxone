resource "random_string" "random_suffix" {
  length  = 6
  special = false
  upper   = false
}

locals {
  s3_bucket_name_suffix = "${var.deployment_id}-${random_string.random_suffix.result}"
}

# UPLOADS BUCKET
# S3 Bucket
# tfsec:ignore:aws-s3-encryption-customer-key
resource "aws_s3_bucket" "uploads_bucket" {
  bucket        = "uploads-${lower(local.s3_bucket_name_suffix)}"
  force_destroy = true

  tags = {
    Name        = "${var.deployment_id} uploads bucket"
    Environment = "${var.deployment_id}"
  }
}

# S3 Bucket - acl
resource "aws_s3_bucket_acl" "uploads_bucket_acl" {
  bucket = aws_s3_bucket.uploads_bucket.id
  acl    = "private"
}

# S3 Bucket - versioning
resource "aws_s3_bucket_versioning" "uploads_bucket_versioning" {
  bucket = aws_s3_bucket.uploads_bucket.id

  versioning_configuration {
    status = var.s3_bucket_versioning_status
  }
}

# S3 Bucket - encryption configuration
resource "aws_s3_bucket_server_side_encryption_configuration" "uploads_bucket_encryption_configuration" {
  bucket = aws_s3_bucket.uploads_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# S3 Bucket - lifecycle
resource "aws_s3_bucket_lifecycle_configuration" "uploads_bucket_lifecycle" {
  bucket = aws_s3_bucket.uploads_bucket.id

  rule {
    id     = "Transition-To-Intelligent-Tiering"
    status = "Enabled"
    # abort_incomplete_multipart_upload_days = 1 (not expected here)
    transition {
      days          = 0
      storage_class = "INTELLIGENT_TIERING"
    }
  }
  rule {
    id     = "${var.s3_retention_period}-Days-Non-Current-Expiration"
    status = "Enabled"
    noncurrent_version_expiration {
      noncurrent_days = var.s3_retention_period
    }
    expiration {
      expired_object_delete_marker = true
    }
  }
}

# S3 Bucket - Ownership Control
resource "aws_s3_bucket_ownership_controls" "uploads_ownership_controls" {
  bucket  = aws_s3_bucket.uploads_bucket.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

# S3 Bucket - Block Public Access
resource "aws_s3_bucket_public_access_block" "uploads_public_access_block" {
  bucket                  = aws_s3_bucket.uploads_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true  
}

# S3 Bucket Policy - Deny Non-HTTPS only
resource "aws_s3_bucket_policy" "uploads_permissive_access" {
  bucket  = aws_s3_bucket.uploads_bucket.id
  policy = jsonencode({
      "Version": "2012-10-17",
      "Statement": [
        {
          "Sid": "denyInsecureTransport",
          "Effect": "Deny",
          "Principal": "*",
          "Action": "s3:*",
          "Resource": [
            "arn:aws:s3:::${aws_s3_bucket.uploads_bucket.id}/*",
            "arn:aws:s3:::${aws_s3_bucket.uploads_bucket.id}"
          ],
          "Condition": {
            "Bool": {
                "aws:SecureTransport": "false"
            }
          }
        }
      ]
  })
}

# QUERIES BUCKET
# S3 Bucket
# tfsec:ignore:aws-s3-encryption-customer-key
resource "aws_s3_bucket" "queries_bucket" {
  bucket = "queries-${lower(local.s3_bucket_name_suffix)}"
  force_destroy = true

  tags = {
    Name        = "${var.deployment_id} queries bucket"
    Environment = "${var.deployment_id}"
  }
}

# S3 Bucket - acl
resource "aws_s3_bucket_acl" "queries_bucket_acl" {
  bucket = aws_s3_bucket.queries_bucket.id
  acl    = "private"
}

# S3 Bucket - versioning
resource "aws_s3_bucket_versioning" "queries_bucket_versioning" {
  bucket = aws_s3_bucket.queries_bucket.id

  versioning_configuration {
    status = var.s3_bucket_versioning_status
  }
}

# S3 Bucket - encryption configuration
resource "aws_s3_bucket_server_side_encryption_configuration" "queries_bucket_encryption_configuration" {
  bucket = aws_s3_bucket.queries_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# S3 Bucket - lifecycle
resource "aws_s3_bucket_lifecycle_configuration" "queries_bucket_lifecycle" {
  bucket = aws_s3_bucket.queries_bucket.id

  rule {
    id     = "Transition-To-Intelligent-Tiering"
    status = "Enabled"
    # abort_incomplete_multipart_upload_days = 1 (not expected here)
    transition {
      days          = 0
      storage_class = "INTELLIGENT_TIERING"
    }
  }
  rule {
    id     = "${var.s3_retention_period}-Days-Non-Current-Expiration"
    status = "Enabled"
    noncurrent_version_expiration {
      noncurrent_days = var.s3_retention_period
    }
    expiration {
      expired_object_delete_marker = true
    }
  }
}

# S3 Bucket - Ownership Control
resource "aws_s3_bucket_ownership_controls" "queries_ownership" {
  bucket  = aws_s3_bucket.queries_bucket.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

# S3 Bucket - Block Public Access
resource "aws_s3_bucket_public_access_block" "queries_public_access_block" {
  bucket                  = aws_s3_bucket.queries_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true  
}

# S3 Bucket Policy - Deny Non-HTTPS only
resource "aws_s3_bucket_policy" "queries_permissive_access" {
  bucket  = aws_s3_bucket.queries_bucket.id
  policy = jsonencode({
      "Version": "2012-10-17",
      "Statement": [
        {
          "Sid": "denyInsecureTransport",
          "Effect": "Deny",
          "Principal": "*",
          "Action": "s3:*",
          "Resource": [
            "arn:aws:s3:::${aws_s3_bucket.queries_bucket.id}/*",
            "arn:aws:s3:::${aws_s3_bucket.queries_bucket.id}"
          ],
          "Condition": {
            "Bool": {
                "aws:SecureTransport": "false"
            }
          }
        }
      ]
  })
}

# MISC BUCKET
# S3 Bucket
# tfsec:ignore:aws-s3-encryption-customer-key
resource "aws_s3_bucket" "misc_bucket" {
  bucket = "misc-${lower(local.s3_bucket_name_suffix)}"
  force_destroy = true

  tags = {
    Name        = "${var.deployment_id} misc bucket"
    Environment = "${var.deployment_id}"
  }
}

# S3 Bucket - acl
resource "aws_s3_bucket_acl" "misc_bucket_acl" {
  bucket = aws_s3_bucket.misc_bucket.id
  acl    = "private"
}

# S3 Bucket - versioning
resource "aws_s3_bucket_versioning" "misc_bucket_versioning" {
  bucket = aws_s3_bucket.misc_bucket.id

  versioning_configuration {
    status = var.s3_bucket_versioning_status
  }
}

# S3 Bucket - encryption configuration
resource "aws_s3_bucket_server_side_encryption_configuration" "misc_bucket_encryption_configuration" {
  bucket = aws_s3_bucket.misc_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# S3 Bucket - lifecycle
resource "aws_s3_bucket_lifecycle_configuration" "misc_bucket_lifecycle" {
  bucket = aws_s3_bucket.misc_bucket.id

  rule {
    id     = "Transition-To-Intelligent-Tiering"
    status = "Enabled"
    # abort_incomplete_multipart_upload_days = 1 (not expected here)
    transition {
      days          = 0
      storage_class = "INTELLIGENT_TIERING"
    }
  }
  rule {
    id     = "${var.s3_retention_period}-Days-Non-Current-Expiration"
    status = "Enabled"
    noncurrent_version_expiration {
      noncurrent_days = var.s3_retention_period
    }
    expiration {
      expired_object_delete_marker = true
    }
  }
}

# S3 Bucket - Ownership Control
resource "aws_s3_bucket_ownership_controls" "misc_ownership" {
  bucket  = aws_s3_bucket.misc_bucket.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

# S3 Bucket - Block Public Access
resource "aws_s3_bucket_public_access_block" "misc_public_access_block" {
  bucket                  = aws_s3_bucket.misc_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true  
}

# S3 Bucket Policy - Deny Non-HTTPS only
resource "aws_s3_bucket_policy" "misc_permissive_access" {
  bucket  = aws_s3_bucket.misc_bucket.id
  policy = jsonencode({
      "Version": "2012-10-17",
      "Statement": [
        {
          "Sid": "denyInsecureTransport",
          "Effect": "Deny",
          "Principal": "*",
          "Action": "s3:*",
          "Resource": [
            "arn:aws:s3:::${aws_s3_bucket.misc_bucket.id}/*",
            "arn:aws:s3:::${aws_s3_bucket.misc_bucket.id}"
          ],
          "Condition": {
            "Bool": {
                "aws:SecureTransport": "false"
            }
          }
        }
      ]
  })
}

# REPOSTORE BUCKET
# S3 Bucket
# tfsec:ignore:aws-s3-encryption-customer-key
resource "aws_s3_bucket" "repostore_bucket" {
  bucket = "repostore-${lower(local.s3_bucket_name_suffix)}"
  force_destroy = true

  tags = {
    Name        = "${var.deployment_id} repostore bucket"
    Environment = "${var.deployment_id}"
  }
}

# S3 Bucket - acl
resource "aws_s3_bucket_acl" "repostore_bucket_acl" {
  bucket = aws_s3_bucket.repostore_bucket.id
  acl    = "private"
}

# S3 Bucket - versioning
resource "aws_s3_bucket_versioning" "repostore_bucket_versioning" {
  bucket = aws_s3_bucket.repostore_bucket.id

  versioning_configuration {
    status = var.s3_bucket_versioning_status
  }
}

# S3 Bucket - encryption configuration
resource "aws_s3_bucket_server_side_encryption_configuration" "repostore_bucket_encryption_configuration" {
  bucket = aws_s3_bucket.repostore_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# S3 Bucket - lifecycle
resource "aws_s3_bucket_lifecycle_configuration" "repostore_bucket_lifecycle" {
  bucket = aws_s3_bucket.repostore_bucket.id

  rule {
    id     = "Transition-To-Intelligent-Tiering"
    status = "Enabled"
    # abort_incomplete_multipart_upload_days = 1 (not expected here)
    transition {
      days          = 0
      storage_class = "INTELLIGENT_TIERING"
    }
  }
  rule {
    id     = "${var.s3_retention_period}-Days-Non-Current-Expiration"
    status = "Enabled"
    noncurrent_version_expiration {
      noncurrent_days = var.s3_retention_period
    }
    expiration {
      expired_object_delete_marker = true
    }
  }
}

# S3 Bucket - Ownership Control
resource "aws_s3_bucket_ownership_controls" "repostore_ownership_controls" {
  bucket  = aws_s3_bucket.repostore_bucket.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

# S3 Bucket - Block Public Access
resource "aws_s3_bucket_public_access_block" "repostore_public_access_block" {
  bucket                  = aws_s3_bucket.repostore_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true  
}

# S3 Bucket Policy - Deny Non-HTTPS only
resource "aws_s3_bucket_policy" "repostore_permissive_access" {
  bucket  = aws_s3_bucket.repostore_bucket.id
  policy = jsonencode({
      "Version": "2012-10-17",
      "Statement": [
        {
          "Sid": "denyInsecureTransport",
          "Effect": "Deny",
          "Principal": "*",
          "Action": "s3:*",
          "Resource": [
            "arn:aws:s3:::${aws_s3_bucket.repostore_bucket.id}/*",
            "arn:aws:s3:::${aws_s3_bucket.repostore_bucket.id}"
          ],
          "Condition": {
            "Bool": {
                "aws:SecureTransport": "false"
            }
          }
        }
      ]
  })
}

# SAST-METADATA BUCKET
# S3 Bucket
# tfsec:ignore:aws-s3-encryption-customer-key
resource "aws_s3_bucket" "sast_metadata_bucket" {
  bucket = "sast-metadata-${lower(local.s3_bucket_name_suffix)}"
  force_destroy = true

  tags = {
    Name        = "${var.deployment_id} sast metadata bucket"
    Environment = "${var.deployment_id}"
  }
}

# S3 Bucket - acl
resource "aws_s3_bucket_acl" "sast_metadata_acl" {
  bucket = aws_s3_bucket.sast_metadata_bucket.id
  acl    = "private"
}

# S3 Bucket - versioning
resource "aws_s3_bucket_versioning" "sast_metadata_versioning" {
  bucket = aws_s3_bucket.sast_metadata_bucket.id

  versioning_configuration {
    status = var.s3_bucket_versioning_status
  }
}

# S3 Bucket - encryption configuration
resource "aws_s3_bucket_server_side_encryption_configuration" "sast_metadata_encryption_configuration" {
  bucket = aws_s3_bucket.sast_metadata_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# S3 Bucket - lifecycle
resource "aws_s3_bucket_lifecycle_configuration" "sast_metadata_lifecycle" {
  bucket = aws_s3_bucket.sast_metadata_bucket.id

  rule {
    id     = "Transition-To-Intelligent-Tiering"
    status = "Enabled"
    # abort_incomplete_multipart_upload_days = 1 (not expected here)
    transition {
      days          = 0
      storage_class = "INTELLIGENT_TIERING"
    }
  }
  rule {
    id     = "${var.s3_retention_period}-Days-Non-Current-Expiration"
    status = "Enabled"
    noncurrent_version_expiration {
      noncurrent_days = var.s3_retention_period
    }
    expiration {
      expired_object_delete_marker = true
    }
  }
}

# S3 Bucket - Ownership Control
resource "aws_s3_bucket_ownership_controls" "sast_metadata_ownership_controls" {
  bucket  = aws_s3_bucket.sast_metadata_bucket.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

# S3 Bucket - Block Public Access
resource "aws_s3_bucket_public_access_block" "sast_metadata_public_access_block" {
  bucket                  = aws_s3_bucket.sast_metadata_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true  
}

# S3 Bucket Policy - Deny Non-HTTPS only
resource "aws_s3_bucket_policy" "sast_metadata_permissive_access" {
  bucket  = aws_s3_bucket.sast_metadata_bucket.id
  policy = jsonencode({
      "Version": "2012-10-17",
      "Statement": [
        {
          "Sid": "denyInsecureTransport",
          "Effect": "Deny",
          "Principal": "*",
          "Action": "s3:*",
          "Resource": [
            "arn:aws:s3:::${aws_s3_bucket.sast_metadata_bucket.id}/*",
            "arn:aws:s3:::${aws_s3_bucket.sast_metadata_bucket.id}"
          ],
          "Condition": {
            "Bool": {
                "aws:SecureTransport": "false"
            }
          }
        }
      ]
  })
}

# SCANS BUCKET
# S3 Bucket
# tfsec:ignore:aws-s3-encryption-customer-key
resource "aws_s3_bucket" "scans_bucket" {
  bucket = "scans-${lower(local.s3_bucket_name_suffix)}"
  force_destroy = true

  tags = {
    Name        = "${var.deployment_id} scans bucket"
    Environment = "${var.deployment_id}"
  }
}

# S3 Bucket - acl
resource "aws_s3_bucket_acl" "scans_bucket_acl" {
  bucket = aws_s3_bucket.scans_bucket.id
  acl    = "private"
}

# S3 Bucket - versioning
resource "aws_s3_bucket_versioning" "scans_bucket_versioning" {
  bucket = aws_s3_bucket.scans_bucket.id

  versioning_configuration {
    status = var.s3_bucket_versioning_status
  }
}

# S3 Bucket - encryption configuration
resource "aws_s3_bucket_server_side_encryption_configuration" "scans_bucket_encryption_configuration" {
  bucket = aws_s3_bucket.scans_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# S3 Bucket - lifecycle
resource "aws_s3_bucket_lifecycle_configuration" "scans_bucket_lifecycle" {
  bucket = aws_s3_bucket.scans_bucket.id

  rule {
    id     = "Transition-To-Intelligent-Tiering"
    status = "Enabled"
    # abort_incomplete_multipart_upload_days = 1 (not expected here)
    transition {
      days          = 0
      storage_class = "INTELLIGENT_TIERING"
    }
  }
  rule {
    id     = "${var.s3_retention_period}-Days-Non-Current-Expiration"
    status = "Enabled"
    noncurrent_version_expiration {
      noncurrent_days = var.s3_retention_period
    }
    expiration {
      expired_object_delete_marker = true
    }
  }
}

# S3 Bucket - Ownership Control
resource "aws_s3_bucket_ownership_controls" "scans_ownership_controls" {
  bucket  = aws_s3_bucket.scans_bucket.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

# S3 Bucket - Block Public Access
resource "aws_s3_bucket_public_access_block" "scans_public_access_block" {
  bucket                  = aws_s3_bucket.scans_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true  
}

# S3 Bucket Policy - Deny Non-HTTPS only
resource "aws_s3_bucket_policy" "scans_permissive_access" {
  bucket  = aws_s3_bucket.scans_bucket.id
  policy = jsonencode({
      "Version": "2012-10-17",
      "Statement": [
        {
          "Sid": "denyInsecureTransport",
          "Effect": "Deny",
          "Principal": "*",
          "Action": "s3:*",
          "Resource": [
            "arn:aws:s3:::${aws_s3_bucket.scans_bucket.id}/*",
            "arn:aws:s3:::${aws_s3_bucket.scans_bucket.id}"
          ],
          "Condition": {
            "Bool": {
                "aws:SecureTransport": "false"
            }
          }
        }
      ]
  })
}

# SAST-WORKER BUCKET
# S3 Bucket
# tfsec:ignore:aws-s3-encryption-customer-key
resource "aws_s3_bucket" "sast_worker_bucket" {
  bucket = "sast-worker-${lower(local.s3_bucket_name_suffix)}"
  force_destroy = true

  tags = {
    Name        = "${var.deployment_id} sast worker bucket"
    Environment = "${var.deployment_id}"
  }
}

# S3 Bucket - acl
resource "aws_s3_bucket_acl" "sast_worker_bucket_acl" {
  bucket = aws_s3_bucket.sast_worker_bucket.id
  acl    = "private"
}

# S3 Bucket - versioning
resource "aws_s3_bucket_versioning" "sast_worker_bucket_versioning" {
  bucket = aws_s3_bucket.sast_worker_bucket.id

  versioning_configuration {
    status = var.s3_bucket_versioning_status
  }
}

# S3 Bucket - encryption configuration
resource "aws_s3_bucket_server_side_encryption_configuration" "sast_worker_bucket_encryption_configuration" {
  bucket = aws_s3_bucket.sast_worker_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# S3 Bucket - lifecycle
resource "aws_s3_bucket_lifecycle_configuration" "sast_worker_bucket_lifecycle" {
  bucket = aws_s3_bucket.sast_worker_bucket.id

  rule {
    id     = "Transition-To-Intelligent-Tiering"
    status = "Enabled"
    # abort_incomplete_multipart_upload_days = 1 (not expected here)
    transition {
      days          = 0
      storage_class = "INTELLIGENT_TIERING"
    }
  }
  rule {
    id     = "${var.s3_retention_period}-Days-Non-Current-Expiration"
    status = "Enabled"
    noncurrent_version_expiration {
      noncurrent_days = var.s3_retention_period
    }
    expiration {
      expired_object_delete_marker = true
    }
  }
}

# S3 Bucket - Ownership Control
resource "aws_s3_bucket_ownership_controls" "sast_worker_ownership_controls" {
  bucket  = aws_s3_bucket.sast_worker_bucket.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

# S3 Bucket - Block Public Access
resource "aws_s3_bucket_public_access_block" "sast_worker_public_access_block" {
  bucket                  = aws_s3_bucket.sast_worker_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true  
}

# S3 Bucket Policy - Deny Non-HTTPS only
resource "aws_s3_bucket_policy" "sast_worker_permissive_access" {
  bucket  = aws_s3_bucket.sast_worker_bucket.id
  policy = jsonencode({
      "Version": "2012-10-17",
      "Statement": [
        {
          "Sid": "denyInsecureTransport",
          "Effect": "Deny",
          "Principal": "*",
          "Action": "s3:*",
          "Resource": [
            "arn:aws:s3:::${aws_s3_bucket.sast_worker_bucket.id}/*",
            "arn:aws:s3:::${aws_s3_bucket.sast_worker_bucket.id}"
          ],
          "Condition": {
            "Bool": {
                "aws:SecureTransport": "false"
            }
          }
        }
      ]
  })
}

# KICS-WORKER BUCKET
# S3 Bucket
# tfsec:ignore:aws-s3-encryption-customer-key
resource "aws_s3_bucket" "kics_worker_bucket" {
  bucket = "kics-worker-${lower(local.s3_bucket_name_suffix)}"
  force_destroy = true

  tags = {
    Name        = "${var.deployment_id} kics worker bucket"
    Environment = "${var.deployment_id}"
  }
}

# S3 Bucket - acl
resource "aws_s3_bucket_acl" "kics_worker_bucket_acl" {
  bucket = aws_s3_bucket.kics_worker_bucket.id
  acl    = "private"
}

# S3 Bucket - versioning
resource "aws_s3_bucket_versioning" "kics_worker_bucket_versioning" {
  bucket = aws_s3_bucket.kics_worker_bucket.id

  versioning_configuration {
    status = var.s3_bucket_versioning_status
  }
}

# S3 Bucket - encryption configuration
resource "aws_s3_bucket_server_side_encryption_configuration" "kics_worker_bucket_encryption_configuration" {
  bucket = aws_s3_bucket.kics_worker_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# S3 Bucket - lifecycle
resource "aws_s3_bucket_lifecycle_configuration" "kics_worker_bucket_lifecycle" {
  bucket = aws_s3_bucket.kics_worker_bucket.id

  rule {
    id     = "Transition-To-Intelligent-Tiering"
    status = "Enabled"
    # abort_incomplete_multipart_upload_days = 1 (not expected here)
    transition {
      days          = 0
      storage_class = "INTELLIGENT_TIERING"
    }
  }
  rule {
    id     = "${var.s3_retention_period}-Days-Non-Current-Expiration"
    status = "Enabled"
    noncurrent_version_expiration {
      noncurrent_days = var.s3_retention_period
    }
    expiration {
      expired_object_delete_marker = true
    }
  }
}

# S3 Bucket - Ownership Control
resource "aws_s3_bucket_ownership_controls" "kics_worker_ownership_controls" {
  bucket  = aws_s3_bucket.kics_worker_bucket.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

# S3 Bucket - Block Public Access
resource "aws_s3_bucket_public_access_block" "kics_worker_public_access_block" {
  bucket                  = aws_s3_bucket.kics_worker_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true  
}

# S3 Bucket Policy - Deny Non-HTTPS only
resource "aws_s3_bucket_policy" "kics_worker_permissive_access" {
  bucket  = aws_s3_bucket.kics_worker_bucket.id
  policy = jsonencode({
      "Version": "2012-10-17",
      "Statement": [
        {
          "Sid": "denyInsecureTransport",
          "Effect": "Deny",
          "Principal": "*",
          "Action": "s3:*",
          "Resource": [
            "arn:aws:s3:::${aws_s3_bucket.kics_worker_bucket.id}/*",
            "arn:aws:s3:::${aws_s3_bucket.kics_worker_bucket.id}"
          ],
          "Condition": {
            "Bool": {
                "aws:SecureTransport": "false"
            }
          }
        }
      ]
  })
}

# SCA-WORKER BUCKET
# S3 Bucket
# tfsec:ignore:aws-s3-encryption-customer-key
resource "aws_s3_bucket" "sca_worker_bucket" {
  bucket = "sca-worker-${lower(local.s3_bucket_name_suffix)}"
  force_destroy = true

  tags = {
    Name        = "${var.deployment_id} sca worker bucket"
    Environment = "${var.deployment_id}"
  }
}

# S3 Bucket - acl
resource "aws_s3_bucket_acl" "sca_worker_bucket_acl" {
  bucket = aws_s3_bucket.sca_worker_bucket.id
  acl    = "private"
}

# S3 Bucket - versioning
resource "aws_s3_bucket_versioning" "sca_worker_bucket_versioning" {
  bucket = aws_s3_bucket.sca_worker_bucket.id

  versioning_configuration {
    status = var.s3_bucket_versioning_status
  }
}

# S3 Bucket - encryption configuration
resource "aws_s3_bucket_server_side_encryption_configuration" "sca_worker_bucket_encryption_configuration" {
  bucket = aws_s3_bucket.sca_worker_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# S3 Bucket - lifecycle
resource "aws_s3_bucket_lifecycle_configuration" "sca_worker_bucket_lifecycle" {
  bucket = aws_s3_bucket.sca_worker_bucket.id

  rule {
    id     = "Transition-To-Intelligent-Tiering"
    status = "Enabled"
    # abort_incomplete_multipart_upload_days = 1 (not expected here)
    transition {
      days          = 0
      storage_class = "INTELLIGENT_TIERING"
    }
  }
  rule {
    id     = "${var.s3_retention_period}-Days-Non-Current-Expiration"
    status = "Enabled"
    noncurrent_version_expiration {
      noncurrent_days = var.s3_retention_period
    }
    expiration {
      expired_object_delete_marker = true
    }
  }
}

# S3 Bucket - Ownership Control
resource "aws_s3_bucket_ownership_controls" "sca_worker_ownership_controls" {
  bucket  = aws_s3_bucket.sca_worker_bucket.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

# S3 Bucket - Block Public Access
resource "aws_s3_bucket_public_access_block" "sca_worker_public_access_block" {
  bucket                  = aws_s3_bucket.sca_worker_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true  
}

# S3 Bucket Policy - Deny Non-HTTPS only
resource "aws_s3_bucket_policy" "sca_worker_permissive_access" {
  bucket  = aws_s3_bucket.sca_worker_bucket.id
  policy = jsonencode({
      "Version": "2012-10-17",
      "Statement": [
        {
          "Sid": "denyInsecureTransport",
          "Effect": "Deny",
          "Principal": "*",
          "Action": "s3:*",
          "Resource": [
            "arn:aws:s3:::${aws_s3_bucket.sca_worker_bucket.id}/*",
            "arn:aws:s3:::${aws_s3_bucket.sca_worker_bucket.id}"
          ],
          "Condition": {
            "Bool": {
                "aws:SecureTransport": "false"
            }
          }
        }
      ]
  })
}

# LOGS BUCKET
# S3 Bucket
# tfsec:ignore:aws-s3-encryption-customer-key
resource "aws_s3_bucket" "logs_bucket" {
  bucket = "logs-${lower(local.s3_bucket_name_suffix)}"
  force_destroy = true
  
  tags = {
    Name        = "${var.deployment_id} logs bucket"
    Environment = "${var.deployment_id}"
  }
}

# S3 Bucket - acl
resource "aws_s3_bucket_acl" "logs_bucket_acl" {
  bucket = aws_s3_bucket.logs_bucket.id
  acl    = "private"
}

# S3 Bucket - versioning
resource "aws_s3_bucket_versioning" "logs_bucket_versioning" {
  bucket = aws_s3_bucket.logs_bucket.id

  versioning_configuration {
    status = var.s3_bucket_versioning_status
  }
}

# S3 Bucket - encryption configuration
resource "aws_s3_bucket_server_side_encryption_configuration" "logs_bucket_encryption_configuration" {
  bucket = aws_s3_bucket.logs_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# S3 Bucket - lifecycle
resource "aws_s3_bucket_lifecycle_configuration" "logs_bucket_lifecycle" {
  bucket = aws_s3_bucket.logs_bucket.id

  rule {
    id     = "Transition-To-Intelligent-Tiering"
    status = "Enabled"
    # abort_incomplete_multipart_upload_days = 1 (not expected here)
    transition {
      days          = 0
      storage_class = "INTELLIGENT_TIERING"
    }
  }
  rule {
    id     = "${var.s3_retention_period}-Days-Non-Current-Expiration"
    status = "Enabled"
    noncurrent_version_expiration {
      noncurrent_days = var.s3_retention_period
    }
    expiration {
      expired_object_delete_marker = true
    }
  }
}

# S3 Bucket - Ownership Control
resource "aws_s3_bucket_ownership_controls" "logs_bucket_ownership_controls" {
  bucket  = aws_s3_bucket.logs_bucket.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

# S3 Bucket - Block Public Access
resource "aws_s3_bucket_public_access_block" "logs_bucket_public_access_block" {
  bucket                  = aws_s3_bucket.logs_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true  
}

# S3 Bucket Policy - Deny Non-HTTPS only
resource "aws_s3_bucket_policy" "logs_permissive_access" {
  bucket  = aws_s3_bucket.logs_bucket.id
  policy = jsonencode({
      "Version": "2012-10-17",
      "Statement": [
        {
          "Sid": "denyInsecureTransport",
          "Effect": "Deny",
          "Principal": "*",
          "Action": "s3:*",
          "Resource": [
            "arn:aws:s3:::${aws_s3_bucket.logs_bucket.id}/*",
            "arn:aws:s3:::${aws_s3_bucket.logs_bucket.id}"
          ],
          "Condition": {
            "Bool": {
                "aws:SecureTransport": "false"
            }
          }
        }
      ]
  })
}

# ENGINE-LOGS BUCKET
# S3 Bucket
# tfsec:ignore:aws-s3-encryption-customer-key
resource "aws_s3_bucket" "engine_logs_bucket" {
  bucket = "engine-logs-${lower(local.s3_bucket_name_suffix)}"
  force_destroy = true

  tags = {
    Name        = "${var.deployment_id} engine logs bucket"
    Environment = "${var.deployment_id}"
  }
}

# S3 Bucket - acl
resource "aws_s3_bucket_acl" "engine_logs_bucket_acl" {
  bucket = aws_s3_bucket.engine_logs_bucket.id
  acl    = "private"
}

# S3 Bucket - versioning
resource "aws_s3_bucket_versioning" "engine_logs_bucket_versioning" {
  bucket = aws_s3_bucket.engine_logs_bucket.id

  versioning_configuration {
    status = var.s3_bucket_versioning_status
  }
}

# S3 Bucket - encryption configuration
resource "aws_s3_bucket_server_side_encryption_configuration" "engine_logs_bucket_encryption_configuration" {
  bucket = aws_s3_bucket.engine_logs_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# S3 Bucket - lifecycle
resource "aws_s3_bucket_lifecycle_configuration" "engine_logs_bucket_lifecycle" {
  bucket = aws_s3_bucket.engine_logs_bucket.id

  rule {
    id     = "Transition-To-Intelligent-Tiering"
    status = "Enabled"
    # abort_incomplete_multipart_upload_days = 1 (not expected here)
    transition {
      days          = 0
      storage_class = "INTELLIGENT_TIERING"
    }
  }
  rule {
    id     = "${var.s3_retention_period}-Days-Non-Current-Expiration"
    status = "Enabled"
    noncurrent_version_expiration {
      noncurrent_days = var.s3_retention_period
    }
    expiration {
      expired_object_delete_marker = true
    }
  }
}

# S3 Bucket - Ownership Control
resource "aws_s3_bucket_ownership_controls" "engine_logs_ownership_controls" {
  bucket  = aws_s3_bucket.engine_logs_bucket.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

# S3 Bucket - Block Public Access
resource "aws_s3_bucket_public_access_block" "engine_logs_public_access_block" {
  bucket                  = aws_s3_bucket.engine_logs_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true  
}

# S3 Bucket Policy - Deny Non-HTTPS only
resource "aws_s3_bucket_policy" "engine_logs_permissive_access" {
  bucket  = aws_s3_bucket.engine_logs_bucket.id
  policy = jsonencode({
      "Version": "2012-10-17",
      "Statement": [
        {
          "Sid": "denyInsecureTransport",
          "Effect": "Deny",
          "Principal": "*",
          "Action": "s3:*",
          "Resource": [
            "arn:aws:s3:::${aws_s3_bucket.engine_logs_bucket.id}/*",
            "arn:aws:s3:::${aws_s3_bucket.engine_logs_bucket.id}"
          ],
          "Condition": {
            "Bool": {
                "aws:SecureTransport": "false"
            }
          }
        }
      ]
  })
}

# REPORTS BUCKET
# S3 Bucket
# tfsec:ignore:aws-s3-encryption-customer-key
resource "aws_s3_bucket" "reports_bucket" {
  bucket = "reports-${lower(local.s3_bucket_name_suffix)}"
  force_destroy = true
  
  tags = {
    Name        = "${var.deployment_id} reports bucket"
    Environment = "${var.deployment_id}"
  }
}

# S3 Bucket - acl
resource "aws_s3_bucket_acl" "reports_bucket_acl" {
  bucket = aws_s3_bucket.reports_bucket.id
  acl    = "private"
}

# S3 Bucket - versioning
resource "aws_s3_bucket_versioning" "reports_bucket_versioning" {
  bucket = aws_s3_bucket.reports_bucket.id

  versioning_configuration {
    status = var.s3_bucket_versioning_status
  }
}

# S3 Bucket - encryption configuration
resource "aws_s3_bucket_server_side_encryption_configuration" "reports_bucket_encryption_configuration" {
  bucket = aws_s3_bucket.reports_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# S3 Bucket - lifecycle
resource "aws_s3_bucket_lifecycle_configuration" "reports_bucket_lifecycle" {
  bucket = aws_s3_bucket.reports_bucket.id

  rule {
    id     = "Transition-To-Intelligent-Tiering"
    status = "Enabled"
    # abort_incomplete_multipart_upload_days = 1 (not expected here)
    transition {
      days          = 0
      storage_class = "INTELLIGENT_TIERING"
    }
  }
  rule {
    id     = "${var.s3_retention_period}-Days-Non-Current-Expiration"
    status = "Enabled"
    noncurrent_version_expiration {
      noncurrent_days = var.s3_retention_period
    }
    expiration {
      expired_object_delete_marker = true
    }
  }
}

# S3 Bucket - Ownership Control
resource "aws_s3_bucket_ownership_controls" "reports_ownership_controls" {
  bucket  = aws_s3_bucket.reports_bucket.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

# S3 Bucket - Block Public Access
resource "aws_s3_bucket_public_access_block" "reports_public_access_block" {
  bucket                  = aws_s3_bucket.reports_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true  
}

# S3 Bucket Policy - Deny Non-HTTPS only
resource "aws_s3_bucket_policy" "reports_permissive_access" {
  bucket  = aws_s3_bucket.reports_bucket.id
  policy = jsonencode({
      "Version": "2012-10-17",
      "Statement": [
        {
          "Sid": "denyInsecureTransport",
          "Effect": "Deny",
          "Principal": "*",
          "Action": "s3:*",
          "Resource": [
            "arn:aws:s3:::${aws_s3_bucket.reports_bucket.id}/*",
            "arn:aws:s3:::${aws_s3_bucket.reports_bucket.id}"
          ],
          "Condition": {
            "Bool": {
                "aws:SecureTransport": "false"
            }
          }
        }
      ]
  })
}

# REPORT-TEMPLATES BUCKET
# S3 Bucket
# tfsec:ignore:aws-s3-encryption-customer-key
resource "aws_s3_bucket" "report_templates_bucket" {
  bucket = "report-templates-${lower(local.s3_bucket_name_suffix)}"
  force_destroy = true

  tags = {
    Name        = "${var.deployment_id} report templates bucket"
    Environment = "${var.deployment_id}"
  }
}

# S3 Bucket - acl
resource "aws_s3_bucket_acl" "report_templates_bucket_acl" {
  bucket = aws_s3_bucket.report_templates_bucket.id
  acl    = "private"
}

# S3 Bucket - versioning
resource "aws_s3_bucket_versioning" "report_templates_bucket_versioning" {
  bucket = aws_s3_bucket.report_templates_bucket.id

  versioning_configuration {
    status = var.s3_bucket_versioning_status
  }
}

# S3 Bucket - encryption configuration
resource "aws_s3_bucket_server_side_encryption_configuration" "report_templates_bucket_encryption_configuration" {
  bucket = aws_s3_bucket.report_templates_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# S3 Bucket - lifecycle
resource "aws_s3_bucket_lifecycle_configuration" "report_templates_bucket_lifecycle" {
  bucket = aws_s3_bucket.report_templates_bucket.id

  rule {
    id     = "Transition-To-Intelligent-Tiering"
    status = "Enabled"
    # abort_incomplete_multipart_upload_days = 1 (not expected here)
    transition {
      days          = 0
      storage_class = "INTELLIGENT_TIERING"
    }
  }
  rule {
    id     = "${var.s3_retention_period}-Days-Non-Current-Expiration"
    status = "Enabled"
    noncurrent_version_expiration {
      noncurrent_days = var.s3_retention_period
    }
    expiration {
      expired_object_delete_marker = true
    }
  }
}

# S3 Bucket - Ownership Control
resource "aws_s3_bucket_ownership_controls" "report_templates_ownership_controls" {
  bucket  = aws_s3_bucket.report_templates_bucket.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

# S3 Bucket - Block Public Access
resource "aws_s3_bucket_public_access_block" "report_templates_public_access_block" {
  bucket                  = aws_s3_bucket.report_templates_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true  
}

# S3 Bucket Policy - Deny Non-HTTPS only
resource "aws_s3_bucket_policy" "report_templates_permissive_access" {
  bucket  = aws_s3_bucket.report_templates_bucket.id
  policy = jsonencode({
      "Version": "2012-10-17",
      "Statement": [
        {
          "Sid": "denyInsecureTransport",
          "Effect": "Deny",
          "Principal": "*",
          "Action": "s3:*",
          "Resource": [
            "arn:aws:s3:::${aws_s3_bucket.report_templates_bucket.id}/*",
            "arn:aws:s3:::${aws_s3_bucket.report_templates_bucket.id}"
          ],
          "Condition": {
            "Bool": {
                "aws:SecureTransport": "false"
            }
          }
        }
      ]
  })
}

# CONFIGURATION BUCKET
# S3 Bucket
# tfsec:ignore:aws-s3-encryption-customer-key
resource "aws_s3_bucket" "configuration_bucket" {
  bucket = "configuration-${lower(local.s3_bucket_name_suffix)}"
  force_destroy = true

  tags = {
    Name        = "${var.deployment_id} configuration bucket"
    Environment = "${var.deployment_id}"
  }
}

# S3 Bucket - acl
resource "aws_s3_bucket_acl" "configuration_bucket_acl" {
  bucket = aws_s3_bucket.configuration_bucket.id
  acl    = "private"
}

# S3 Bucket - versioning
resource "aws_s3_bucket_versioning" "configuration_bucket_versioning" {
  bucket = aws_s3_bucket.configuration_bucket.id

  versioning_configuration {
    status = var.s3_bucket_versioning_status
  }
}

# S3 Bucket - encryption configuration
resource "aws_s3_bucket_server_side_encryption_configuration" "configuration_bucket_encryption_configuration" {
  bucket = aws_s3_bucket.configuration_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# S3 Bucket - lifecycle
resource "aws_s3_bucket_lifecycle_configuration" "configuration_bucket_lifecycle" {
  bucket = aws_s3_bucket.configuration_bucket.id

  rule {
    id     = "Transition-To-Intelligent-Tiering"
    status = "Enabled"
    # abort_incomplete_multipart_upload_days = 1 (not expected here)
    transition {
      days          = 0
      storage_class = "INTELLIGENT_TIERING"
    }
  }
  rule {
    id     = "${var.s3_retention_period}-Days-Non-Current-Expiration"
    status = "Enabled"
    noncurrent_version_expiration {
      noncurrent_days = var.s3_retention_period
    }
    expiration {
      expired_object_delete_marker = true
    }
  }
}

# S3 Bucket - Ownership Control
resource "aws_s3_bucket_ownership_controls" "configuration_ownership_controls" {
  bucket  = aws_s3_bucket.configuration_bucket.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

# S3 Bucket - Block Public Access
resource "aws_s3_bucket_public_access_block" "configuration_public_access_block" {
  bucket                  = aws_s3_bucket.configuration_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true  
}

# S3 Bucket Policy - Deny Non-HTTPS only
resource "aws_s3_bucket_policy" "configuration_permissive_access" {
  bucket  = aws_s3_bucket.configuration_bucket.id
  policy = jsonencode({
      "Version": "2012-10-17",
      "Statement": [
        {
          "Sid": "denyInsecureTransport",
          "Effect": "Deny",
          "Principal": "*",
          "Action": "s3:*",
          "Resource": [
            "arn:aws:s3:::${aws_s3_bucket.configuration_bucket.id}/*",
            "arn:aws:s3:::${aws_s3_bucket.configuration_bucket.id}"
          ],
          "Condition": {
            "Bool": {
                "aws:SecureTransport": "false"
            }
          }
        }
      ]
  })
}

# IMPORTS BUCKET
# S3 Bucket
# tfsec:ignore:aws-s3-encryption-customer-key
resource "aws_s3_bucket" "imports_bucket" {
  bucket = "imports-${lower(local.s3_bucket_name_suffix)}"
  force_destroy = true

  tags = {
    Name        = "${var.deployment_id} imports bucket"
    Environment = "${var.deployment_id}"
  }
}

# S3 Bucket - acl
resource "aws_s3_bucket_acl" "imports_bucket_acl" {
  bucket = aws_s3_bucket.imports_bucket.id
  acl    = "private"
}

# S3 Bucket - versioning
resource "aws_s3_bucket_versioning" "imports_bucket_versioning" {
  bucket = aws_s3_bucket.imports_bucket.id

  versioning_configuration {
    status = var.s3_bucket_versioning_status
  }
}

# S3 Bucket - encryption configuration
resource "aws_s3_bucket_server_side_encryption_configuration" "imports_bucket_encryption_configuration" {
  bucket = aws_s3_bucket.imports_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# S3 Bucket - lifecycle
resource "aws_s3_bucket_lifecycle_configuration" "imports_bucket_lifecycle" {
  bucket = aws_s3_bucket.imports_bucket.id

  rule {
    id     = "Transition-To-Intelligent-Tiering"
    status = "Enabled"
    # abort_incomplete_multipart_upload_days = 1 (not expected here)
    transition {
      days          = 0
      storage_class = "INTELLIGENT_TIERING"
    }
  }
  rule {
    id     = "${var.s3_retention_period}-Days-Non-Current-Expiration"
    status = "Enabled"
    noncurrent_version_expiration {
      noncurrent_days = var.s3_retention_period
    }
    expiration {
      expired_object_delete_marker = true
    }
  }
}

# S3 Bucket - Ownership Control
resource "aws_s3_bucket_ownership_controls" "imports_ownership_controls" {
  bucket  = aws_s3_bucket.imports_bucket.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

# S3 Bucket - Block Public Access
resource "aws_s3_bucket_public_access_block" "imports_public_access_block" {
  bucket                  = aws_s3_bucket.imports_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true  
}

# S3 Bucket Policy - Deny Non-HTTPS only
resource "aws_s3_bucket_policy" "imports_permissive_access" {
  bucket  = aws_s3_bucket.imports_bucket.id
  policy = jsonencode({
      "Version": "2012-10-17",
      "Statement": [
        {
          "Sid": "denyInsecureTransport",
          "Effect": "Deny",
          "Principal": "*",
          "Action": "s3:*",
          "Resource": [
            "arn:aws:s3:::${aws_s3_bucket.imports_bucket.id}/*",
            "arn:aws:s3:::${aws_s3_bucket.imports_bucket.id}"
          ],
          "Condition": {
            "Bool": {
                "aws:SecureTransport": "false"
            }
          }
        }
      ]
  })
}

# AUDIT BUCKET
# S3 Bucket
# tfsec:ignore:aws-s3-encryption-customer-key
resource "aws_s3_bucket" "audit_bucket" {
  bucket = "audit-${lower(local.s3_bucket_name_suffix)}"
  force_destroy = true

  tags = {
    Name        = "${var.deployment_id} audit bucket"
    Environment = "${var.deployment_id}"
  }
}

# S3 Bucket - acl
resource "aws_s3_bucket_acl" "audit_bucket_acl" {
  bucket = aws_s3_bucket.audit_bucket.id
  acl    = "private"
}

# S3 Bucket - versioning
resource "aws_s3_bucket_versioning" "audit_bucket_versioning" {
  bucket = aws_s3_bucket.audit_bucket.id

  versioning_configuration {
    status = var.s3_bucket_versioning_status
  }
}

# S3 Bucket - encryption configuration
resource "aws_s3_bucket_server_side_encryption_configuration" "audit_bucket_encryption_configuration" {
  bucket = aws_s3_bucket.audit_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# S3 Bucket - lifecycle
resource "aws_s3_bucket_lifecycle_configuration" "audit_bucket_lifecycle" {
  bucket = aws_s3_bucket.audit_bucket.id

  rule {
    id     = "Transition-To-Intelligent-Tiering"
    status = "Enabled"
    # abort_incomplete_multipart_upload_days = 1 (not expected here)
    transition {
      days          = 0
      storage_class = "INTELLIGENT_TIERING"
    }
  }
  rule {
    id     = "${var.s3_retention_period}-Days-Non-Current-Expiration"
    status = "Enabled"
    noncurrent_version_expiration {
      noncurrent_days = var.s3_retention_period
    }
    expiration {
      expired_object_delete_marker = true
    }
  }
}

# S3 Bucket - Ownership Control
resource "aws_s3_bucket_ownership_controls" "audit_ownership_controls" {
  bucket  = aws_s3_bucket.audit_bucket.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

# S3 Bucket - Block Public Access
resource "aws_s3_bucket_public_access_block" "audit_public_access_block" {
  bucket                  = aws_s3_bucket.audit_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true  
}

# S3 Bucket Policy - Deny Non-HTTPS only
resource "aws_s3_bucket_policy" "audit_permissive_access" {
  bucket  = aws_s3_bucket.audit_bucket.id
  policy = jsonencode({
      "Version": "2012-10-17",
      "Statement": [
        {
          "Sid": "denyInsecureTransport",
          "Effect": "Deny",
          "Principal": "*",
          "Action": "s3:*",
          "Resource": [
            "arn:aws:s3:::${aws_s3_bucket.audit_bucket.id}/*",
            "arn:aws:s3:::${aws_s3_bucket.audit_bucket.id}"
          ],
          "Condition": {
            "Bool": {
                "aws:SecureTransport": "false"
            }
          }
        }
      ]
  })
}







# SOURCE-RESOLVER BUCKET 
# S3 Bucket
# tfsec:ignore:aws-s3-encryption-customer-key
resource "aws_s3_bucket" "source_resolver_bucket" {
  bucket = "source-resolver-${lower(local.s3_bucket_name_suffix)}"
  force_destroy = true

  tags = {
    Name        = "${var.deployment_id} source resolver bucket"
    Environment = "${var.deployment_id}"
  }
}

# S3 Bucket - acl
resource "aws_s3_bucket_acl" "asource_resolver_bucket_acl" {
  bucket = aws_s3_bucket.source_resolver_bucket.id
  acl    = "private"
}

# S3 Bucket - versioning
resource "aws_s3_bucket_versioning" "source_resolver_bucket_versioning" {
  bucket = aws_s3_bucket.source_resolver_bucket.id

  versioning_configuration {
    status = var.s3_bucket_versioning_status
  }
}

# S3 Bucket - encryption configuration
resource "aws_s3_bucket_server_side_encryption_configuration" "source_resolver_bucket_encryption_configuration" {
  bucket = aws_s3_bucket.source_resolver_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# S3 Bucket - lifecycle
resource "aws_s3_bucket_lifecycle_configuration" "source_resolver_bucket_lifecycle" {
  bucket = aws_s3_bucket.source_resolver_bucket.id

  rule {
    id     = "Transition-To-Intelligent-Tiering"
    status = "Enabled"
    # abort_incomplete_multipart_upload_days = 1 (not expected here)
    transition {
      days          = 0
      storage_class = "INTELLIGENT_TIERING"
    }
  }
  rule {
    id     = "${var.s3_retention_period}-Days-Non-Current-Expiration"
    status = "Enabled"
    noncurrent_version_expiration {
      noncurrent_days = var.s3_retention_period
    }
    expiration {
      expired_object_delete_marker = true
    }
  }
}

# S3 Bucket - Ownership Control
resource "aws_s3_bucket_ownership_controls" "source_resolver_ownership_controls" {
  bucket  = aws_s3_bucket.source_resolver_bucket.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

# S3 Bucket - Block Public Access
resource "aws_s3_bucket_public_access_block" "source_resolver_public_access_block" {
  bucket                  = aws_s3_bucket.source_resolver_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true  
}

# S3 Bucket Policy - Deny Non-HTTPS only
resource "aws_s3_bucket_policy" "source_resolver_permissive_access" {
  bucket  = aws_s3_bucket.source_resolver_bucket.id
  policy = jsonencode({
      "Version": "2012-10-17",
      "Statement": [
        {
          "Sid": "denyInsecureTransport",
          "Effect": "Deny",
          "Principal": "*",
          "Action": "s3:*",
          "Resource": [
            "arn:aws:s3:::${aws_s3_bucket.source_resolver_bucket.id}/*",
            "arn:aws:s3:::${aws_s3_bucket.source_resolver_bucket.id}"
          ],
          "Condition": {
            "Bool": {
                "aws:SecureTransport": "false"
            }
          }
        }
      ]
  })
}




# APISEC BUCKET
# tfsec:ignore:aws-s3-encryption-customer-key
resource "aws_s3_bucket" "apisec_bucket" {
  bucket = "apisec-${lower(local.s3_bucket_name_suffix)}"
  force_destroy = true

  tags = {
    Name        = "${var.deployment_id} apisec bucket"
    Environment = "${var.deployment_id}"
  }
}

# S3 Bucket - acl
resource "aws_s3_bucket_acl" "apisec_bucket_acl" {
  bucket = aws_s3_bucket.apisec_bucket.id
  acl    = "private"
}

# S3 Bucket - versioning
resource "aws_s3_bucket_versioning" "apisec_bucket_versioning" {
  bucket = aws_s3_bucket.apisec_bucket.id

  versioning_configuration {
    status = var.s3_bucket_versioning_status
  }
}

# S3 Bucket - encryption configuration
resource "aws_s3_bucket_server_side_encryption_configuration" "apisec_bucket_encryption_configuration" {
  bucket = aws_s3_bucket.apisec_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# S3 Bucket - lifecycle
resource "aws_s3_bucket_lifecycle_configuration" "apisec_bucket_lifecycle" {
  bucket = aws_s3_bucket.apisec_bucket.id

  rule {
    id     = "Transition-To-Intelligent-Tiering"
    status = "Enabled"
    # abort_incomplete_multipart_upload_days = 1 (not expected here)
    transition {
      days          = 0
      storage_class = "INTELLIGENT_TIERING"
    }
  }
  rule {
    id     = "${var.s3_retention_period}-Days-Non-Current-Expiration"
    status = "Enabled"
    noncurrent_version_expiration {
      noncurrent_days = var.s3_retention_period
    }
    expiration {
      expired_object_delete_marker = true
    }
  }
}

# S3 Bucket - Ownership Control
resource "aws_s3_bucket_ownership_controls" "apisec_ownership_controls" {
  bucket  = aws_s3_bucket.apisec_bucket.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

# S3 Bucket - Block Public Access
resource "aws_s3_bucket_public_access_block" "apisec_public_access_block" {
  bucket                  = aws_s3_bucket.apisec_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true  
}

# S3 Bucket Policy - Deny Non-HTTPS only
resource "aws_s3_bucket_policy" "apisec_permissive_access" {
  bucket  = aws_s3_bucket.apisec_bucket.id
  policy = jsonencode({
      "Version": "2012-10-17",
      "Statement": [
        {
          "Sid": "denyInsecureTransport",
          "Effect": "Deny",
          "Principal": "*",
          "Action": "s3:*",
          "Resource": [
            "arn:aws:s3:::${aws_s3_bucket.apisec_bucket.id}/*",
            "arn:aws:s3:::${aws_s3_bucket.apisec_bucket.id}"
          ],
          "Condition": {
            "Bool": {
                "aws:SecureTransport": "false"
            }
          }
        }
      ]
  })
}

# KICS-MATADATA BUCKET
# S3 Bucket
# tfsec:ignore:aws-s3-encryption-customer-key
resource "aws_s3_bucket" "kics_metadata_bucket" {
  bucket = "kics-metadata-${lower(local.s3_bucket_name_suffix)}"
  force_destroy = true

  tags = {
    Name        = "${var.deployment_id} kics metadata bucket"
    Environment = "${var.deployment_id}"
  }
}

# S3 Bucket - acl
resource "aws_s3_bucket_acl" "kics_metadata_bucket_acl" {
  bucket = aws_s3_bucket.kics_metadata_bucket.id
  acl    = "private"
}

# S3 Bucket - versioning
resource "aws_s3_bucket_versioning" "kics_metadata_bucket_versioning" {
  bucket = aws_s3_bucket.kics_metadata_bucket.id

  versioning_configuration {
    status = var.s3_bucket_versioning_status
  }
}

# S3 Bucket - encryption configuration
resource "aws_s3_bucket_server_side_encryption_configuration" "kics_metadata_bucket_encryption_configuration" {
  bucket = aws_s3_bucket.kics_metadata_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# S3 Bucket - lifecycle
resource "aws_s3_bucket_lifecycle_configuration" "kics_metadata_bucket_lifecycle" {
  bucket = aws_s3_bucket.kics_metadata_bucket.id

  rule {
    id     = "Transition-To-Intelligent-Tiering"
    status = "Enabled"
    # abort_incomplete_multipart_upload_days = 1 (not expected here)
    transition {
      days          = 0
      storage_class = "INTELLIGENT_TIERING"
    }
  }
  rule {
    id     = "${var.s3_retention_period}-Days-Non-Current-Expiration"
    status = "Enabled"
    noncurrent_version_expiration {
      noncurrent_days = var.s3_retention_period
    }
    expiration {
      expired_object_delete_marker = true
    }
  }
}

# S3 Bucket - Ownership Control
resource "aws_s3_bucket_ownership_controls" "kics_metadata_ownership_controls" {
  bucket  = aws_s3_bucket.kics_metadata_bucket.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

# S3 Bucket - Block Public Access
resource "aws_s3_bucket_public_access_block" "kics_metadata_public_access_block" {
  bucket                  = aws_s3_bucket.kics_metadata_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true  
}

# S3 Bucket Policy - Deny Non-HTTPS only
resource "aws_s3_bucket_policy" "kics_metadata_permissive_access" {
  bucket  = aws_s3_bucket.kics_metadata_bucket.id
  policy = jsonencode({
      "Version": "2012-10-17",
      "Statement": [
        {
          "Sid": "denyInsecureTransport",
          "Effect": "Deny",
          "Principal": "*",
          "Action": "s3:*",
          "Resource": [
            "arn:aws:s3:::${aws_s3_bucket.kics_metadata_bucket.id}/*",
            "arn:aws:s3:::${aws_s3_bucket.kics_metadata_bucket.id}"
          ],
          "Condition": {
            "Bool": {
                "aws:SecureTransport": "false"
            }
          }
        }
      ]
  })
}

# REDIS-SHARED-BUCKET
# S3 Bucket
# tfsec:ignore:aws-s3-encryption-customer-key
resource "aws_s3_bucket" "redis_shared_bucket" {
  bucket = "redis-shared-bucket-${lower(local.s3_bucket_name_suffix)}"
  force_destroy = false

  tags = {
    Name        = "${var.deployment_id} redis shared bucket"
    Environment = "${var.deployment_id}"
  }
}

# S3 Bucket - acl
resource "aws_s3_bucket_acl" "redis_shared_bucket_acl" {
  bucket = aws_s3_bucket.redis_shared_bucket.id
  acl    = "private"
}

# S3 Bucket - versioning
resource "aws_s3_bucket_versioning" "redis_shared_bucket_versioning" {
  bucket = aws_s3_bucket.redis_shared_bucket.id

  versioning_configuration {
    status = var.s3_bucket_versioning_status
  }
}

# S3 Bucket - encryption configuration
resource "aws_s3_bucket_server_side_encryption_configuration" "redis_shared_bucket_encryption_configuration" {
  bucket = aws_s3_bucket.redis_shared_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# S3 Bucket - lifecycle
resource "aws_s3_bucket_lifecycle_configuration" "redis_shared_bucket_lifecycle" {
  bucket = aws_s3_bucket.redis_shared_bucket.id

  rule {
    id     = "Transition-To-Intelligent-Tiering"
    status = "Enabled"
    # abort_incomplete_multipart_upload_days = 1 (not expected here)
    transition {
      days          = 0
      storage_class = "INTELLIGENT_TIERING"
    }
  }
  rule {
    id     = "${var.s3_retention_period}-Days-Non-Current-Expiration"
    status = "Enabled"
    noncurrent_version_expiration {
      noncurrent_days = var.s3_retention_period
    }
    expiration {
      expired_object_delete_marker = true
    }
  }
}

# S3 Bucket - Ownership Control
resource "aws_s3_bucket_ownership_controls" "redis_shared_bucket_ownership_controls" {
  bucket  = aws_s3_bucket.redis_shared_bucket.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

# S3 Bucket - Block Public Access
resource "aws_s3_bucket_public_access_block" "redis_shared_bucket_public_access_block" {
  bucket                  = aws_s3_bucket.redis_shared_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true  
}

# S3 Bucket Policy - Deny Non-HTTPS only
resource "aws_s3_bucket_policy" "redis_shared_bucket_permissive_access" {
  bucket  = aws_s3_bucket.redis_shared_bucket.id
  policy = jsonencode({
      "Version": "2012-10-17",
      "Statement": [
        {
          "Sid": "denyInsecureTransport",
          "Effect": "Deny",
          "Principal": "*",
          "Action": "s3:*",
          "Resource": [
            "arn:aws:s3:::${aws_s3_bucket.redis_shared_bucket.id}/*",
            "arn:aws:s3:::${aws_s3_bucket.redis_shared_bucket.id}"
          ],
          "Condition": {
            "Bool": {
                "aws:SecureTransport": "false"
            }
          }
        }
      ]
  })
}

# SCAN-RESULTS-STORAGE
# S3 Bucket
# tfsec:ignore:aws-s3-encryption-customer-key
resource "aws_s3_bucket" "scan_results_storage_bucket" {
  bucket = "scan-results-storage-${lower(local.s3_bucket_name_suffix)}"
  force_destroy = false

  tags = {
    Name        = "${var.deployment_id} scan results storage bucket"
    Environment = "${var.deployment_id}"
  }
}

# S3 Bucket - acl
resource "aws_s3_bucket_acl" "scan_results_storage_bucket_acl" {
  bucket = aws_s3_bucket.scan_results_storage_bucket.id
  acl    = "private"
}

# S3 Bucket - versioning
resource "aws_s3_bucket_versioning" "scan_results_storage_bucket_versioning" {
  bucket = aws_s3_bucket.scan_results_storage_bucket.id

  versioning_configuration {
    status = var.s3_bucket_versioning_status
  }
}

# S3 Bucket - encryption configuration
resource "aws_s3_bucket_server_side_encryption_configuration" "scan_results_storage_bucket_encryption_configuration" {
  bucket = aws_s3_bucket.scan_results_storage_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# S3 Bucket - lifecycle
resource "aws_s3_bucket_lifecycle_configuration" "scan_results_storage_bucket_lifecycle" {
  bucket = aws_s3_bucket.scan_results_storage_bucket.id

  rule {
    id     = "Transition-To-Intelligent-Tiering"
    status = "Enabled"
    # abort_incomplete_multipart_upload_days = 1 (not expected here)
    transition {
      days          = 0
      storage_class = "INTELLIGENT_TIERING"
    }
  }
  rule {
    id     = "${var.s3_retention_period}-Days-Non-Current-Expiration"
    status = "Enabled"
    noncurrent_version_expiration {
      noncurrent_days = var.s3_retention_period
    }
    expiration {
      expired_object_delete_marker = true
    }
  }
}

# S3 Bucket - Ownership Control
resource "aws_s3_bucket_ownership_controls" "scan_results_storage_bucket_ownership_controls" {
  bucket  = aws_s3_bucket.scan_results_storage_bucket.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

# S3 Bucket - Block Public Access
resource "aws_s3_bucket_public_access_block" "scan_results_storage_bucket_public_access_block" {
  bucket                  = aws_s3_bucket.scan_results_storage_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true  
}

# S3 Bucket Policy - Deny Non-HTTPS only
resource "aws_s3_bucket_policy" "scan_results_storage_bucket_permissive_access" {
  bucket  = aws_s3_bucket.scan_results_storage_bucket.id
  policy = jsonencode({
      "Version": "2012-10-17",
      "Statement": [
        {
          "Sid": "denyInsecureTransport",
          "Effect": "Deny",
          "Principal": "*",
          "Action": "s3:*",
          "Resource": [
            "arn:aws:s3:::${aws_s3_bucket.scan_results_storage_bucket.id}/*",
            "arn:aws:s3:::${aws_s3_bucket.scan_results_storage_bucket.id}"
          ],
          "Condition": {
            "Bool": {
                "aws:SecureTransport": "false"
            }
          }
        }
      ]
  })
}

# Policy to Allow Minio Nodegroup to aceess the S3 Buckets
resource "aws_iam_policy" "ast_s3_buckets_policy" {
  name          = "${local.deployment_id}-eks-ng-minio-gateway-S3-${random_string.random_suffix.result}"
  policy        = jsonencode({
    "Version": "2012-10-17",
    "Statement": [
      {
        "Action": [
          "s3:*"
        ],
        "Effect": "Allow",
        "Resource": [
          "arn:aws:s3:::*${lower(local.s3_bucket_name_suffix)}",
          "arn:aws:s3:::*${lower(local.s3_bucket_name_suffix)}/*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ast_s3_buckets_policy_attachment" {
  role       = module.minio_gateway_nodes.iam_role_name
  policy_arn = aws_iam_policy.ast_s3_buckets_policy.arn
}