locals {
  version = "0.25.2"
  api_token_arn = (var.secretsmanager_arn_override == null) ? format("arn:aws:secretsmanager:%s:%s:secret:customer/%s", local.xo_account_region, var.xo_account_id, var.customer_id) : var.secretsmanager_arn_override
  api_token_pattern = (var.secretsmanager_arn_override == null) ? format("arn:aws:secretsmanager:%s:%s:secret:customer/%s-??????", local.xo_account_region, var.xo_account_id, var.customer_id) : var.secretsmanager_arn_override
  kms_key_pattern = format("arn:aws:kms:%s:%s:key/*", local.xo_account_region, var.xo_account_id)
  s3_bucket = "xosphere-io-releases-${data.aws_region.current.name}"
  xo_account_region = "us-west-2"

  enable_xosphere_customer_inventory_cmk_tag = var.xosphere_customer_inventory_cmk_custom_tag_name != null && var.xosphere_customer_inventory_cmk_custom_tag_value != null

  enable_org_inv_mgmt_xosphere = var.organization_inventory_management == "xosphere"
  enable_org_inv_mgmt_customer = var.organization_inventory_management == "customer-provided"

  # mappings
  well_known_names_xosphere_event_router_lambda_role = "xosphere-event-router-lambda-role"
  well_known_names_xosphere_organization_instance_state_event_collector_queue_name = "xosphere-instance-orchestrator-org-inst-state-event-collector-launch"
  well_known_names_xosphere_organization_inventory_collector_role = "xosphere-instance-orchestrator-org-inv-collector-assume-role"
  well_known_names_xosphere_organization_inventory_realtime_updates_event_bus_name = "xosphere-instance-orchestrator-org-inv-realtime-updates-bus"
  well_known_names_xosphere_organization_inventory_realtime_updates_submitter = "xosphere-instance-orchestrator-org-inv-upd-sub"
  well_known_names_xosphere_organization_inventory_realtime_updates_relayer = "xosphere-instance-orchestrator-org-inv-upd-rly"
  lambda_function_map_xosphere_organization_ri_data_gatherer = "xosphere-org-ri-data-gatherer"
  lambda_function_map_xosphere_organization_inventory_customer_parser = "xosphere-org-inv-customer-parser"
  lambda_function_map_xosphere_organization_inventory_data_processor = "xosphere-org-inv-data-processor"
  lambda_function_map_xosphere_organization_ri_data_merger = "xosphere-org-ri-data-merger"
  lambda_function_map_xosphere_organization_ri_sub_account_reporter = "xosphere-org-ri-sub-acct-reporter"
  lambda_function_map_xosphere_organization_ri_sub_account_requester = "xosphere-org-ri-sub-acct-requester"
  lambda_function_map_xosphere_organization_ri_sub_account_submission_processor = "xosphere-org-ri-sub-acct-processor"
  lambda_function_map_xosphere_organization_instance_state_event_collector = "xosphere-org-inst-state-event-collector"
  lambda_function_map_xosphere_organization_inventory_baseline_requester = "xosphere-org-inv-baseline-requester"
  lambda_function_map_xosphere_organization_inventory_baseline_reporter = "xosphere-org-inv-baseline-reporter"
  lambda_function_map_xosphere_organization_inventory_baseline_merger = "xosphere-org-inv-baseline-merger"
  lambda_function_map_xosphere_organization_inventory_data_enricher = "xosphere-org-inv-data-enricher"
  endpoints_map_xosphere_api_endpoint = "https://portal-api.xosphere.io/v1"
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

resource "aws_s3_bucket" "organization_data_access_logs_bucket" {
  count = var.create_logging_buckets ? 1 : 0
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "aws:kms"
        kms_master_key_id = aws_kms_key.xosphere_mgmt_cmk.arn
      }
    }
  }
  force_destroy = true
  bucket_prefix = var.organization_data_access_logs_bucket_name_override == null ? "organization_data_bucket_access_logs" : null
  bucket = var.organization_data_access_logs_bucket_name_override == null ? null : var.organization_data_access_logs_bucket_name_override
}

resource "aws_s3_bucket_public_access_block" "organization_data_access_logs_bucket" {
  count = var.create_logging_buckets ? 1 : 0
  bucket = aws_s3_bucket.organization_data_access_logs_bucket[0].id

  block_public_acls   = true
  block_public_policy = true
  ignore_public_acls = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "organization_data_access_logs_bucket_policy" {
  count = var.create_logging_buckets ? 1 : 0
  bucket = aws_s3_bucket.organization_data_access_logs_bucket[0].id
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "S3ServerAccessLogsPolicy",
      "Resource": "${aws_s3_bucket.organization_data_access_logs_bucket[0].arn}/*",
      "Effect": "Allow",
      "Principal": {
        "Service": "logging.s3.amazonaws.com"
      },
      "Action": [
        "s3:PutObject"
      ],
      "Condition": {
        "ArnLike": {
          "aws:SourceArn": "${aws_s3_bucket.organization_data_bucket.arn}"
        },
        "StringEquals": {
          "aws:SourceAccount": "${data.aws_caller_identity.current.account_id}"
        }
      }
    },
    {
      "Action": [
        "s3:PutObject",
        "s3:GetObject"
      ],
      "Effect": "Allow",
      "Resource": "${aws_s3_bucket.organization_data_access_logs_bucket[0].arn}/*",
      "Principal": {
        "AWS": "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
      }
    }    
  ]
}
EOF
}

resource "aws_s3_bucket" "organization_data_bucket" {
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "aws:kms"
        kms_master_key_id = aws_kms_key.xosphere_mgmt_cmk.arn
      }
    }
  }

  dynamic "logging" {
    for_each = var.create_logging_buckets ? [1] : []
    content {
      target_bucket = var.create_logging_buckets ? aws_s3_bucket.organization_data_access_logs_bucket[0].id : null
      target_prefix = var.create_logging_buckets ? "xosphere-org-data-logs" : null
    }
  }
  force_destroy = true
  bucket_prefix = var.organization_data_bucket_name_override == null ? "organization_data_bucket" : null
  bucket = var.organization_data_bucket_name_override == null ? null : var.organization_data_bucket_name_override
}

resource "aws_s3_bucket_public_access_block" "organization_data_bucket" {
  bucket = aws_s3_bucket.organization_data_bucket.id

  block_public_acls   = true
  block_public_policy = true
  ignore_public_acls = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "organization_data_bucket_policy" {
  bucket = aws_s3_bucket.organization_data_bucket.id
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "s3:GetObject",
        "s3:GetObjectVersion",
        "s3:GetObjectVersionTagging",
        "s3:PutObject",
        "s3:PutObjectTagging",
        "s3:PutObjectVersionTagging",
        "s3:DeleteObject"
      ],
      "Effect": "Allow",
      "Resource": "${aws_s3_bucket.organization_data_bucket.arn}/*",
      "Principal": {
        "AWS": "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
      }
    },
    {
      "Action": [
        "s3:ListBucket",
        "s3:ListBucketVersions"
      ],
      "Effect": "Allow",
      "Resource": "${aws_s3_bucket.organization_data_bucket.arn}",
      "Principal": {
        "AWS": "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
      }
    },
    {
      "Action": [
        "s3:GetObject"
      ],
      "Effect": "Allow",
      "Resource": "${aws_s3_bucket.organization_data_bucket.arn}/*",
      "Principal": "*",
      "Condition": {
        "StringEquals": {
          "aws:PrincipalOrgID": "${var.aws_organization_id}" %{ if false } # should use a pseudo parameter, but AWS doesn't yet provide one.  https://github.com/aws-cloudformation/cloudformation-coverage-roadmap/issues/160 %{ endif }
        }
%{ if var.enable_enhanced_security }        
        ,
        "ArnLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/xosphere-*"
        }
%{ endif }
      }
    },
    {
      "Action": [
        "s3:ListBucket"
      ],
      "Effect": "Allow",
      "Resource": "${aws_s3_bucket.organization_data_bucket.arn}",
      "Principal": "*",
      "Condition": {
        "StringEquals": {
          "aws:PrincipalOrgID": "${var.aws_organization_id}" %{ if false } # should use a pseudo parameter, but AWS doesn't yet provide one.  https://github.com/aws-cloudformation/cloudformation-coverage-roadmap/issues/160 %{ endif }
        }
%{ if var.enable_enhanced_security }
        ,
        "ArnLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/xosphere-*"
        }
%{ endif }
      }
    }
  ]
}
EOF
}

resource "aws_s3_bucket" "customer_inventory_bucket" {
  count = local.enable_org_inv_mgmt_customer ? 1 : 0
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "aws:kms"
        kms_master_key_id = aws_kms_key.xosphere_mgmt_cmk.arn
      }
    }
  }

  dynamic "logging" {
    for_each = var.create_logging_buckets ? [1] : []
    content {
      target_bucket = var.create_logging_buckets ? aws_s3_bucket.organization_data_access_logs_bucket[0].id : null
      target_prefix = var.create_logging_buckets ? "xosphere-org-inv-data-logs" : null
    }
  }
  force_destroy = true
  bucket = var.customer_inventory_bucket_name_override != null ? var.customer_inventory_bucket_name_override : "xosphere-io-mgmt-${data.aws_region.current.name}-${data.aws_caller_identity.current.account_id}-inventory"
}

resource "aws_s3_bucket_public_access_block" "customer_inventory_bucket" {
  count = local.enable_org_inv_mgmt_customer ? 1 : 0
  bucket = aws_s3_bucket.customer_inventory_bucket[0].id

  block_public_acls   = true
  block_public_policy = true
  ignore_public_acls = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_notification" "customer_inventory_bucket" {
  count = local.enable_org_inv_mgmt_customer ? 1 : 0
  bucket = aws_s3_bucket.customer_inventory_bucket[0].id

  queue {
    queue_arn     = aws_sqs_queue.xosphere_organization_inventory_customer_parser_queue[0].arn
    events        = ["s3:ObjectCreated:*"]
  }

  depends_on = [
    aws_sqs_queue_policy.xosphere_organization_inventory_customer_parser_queue_policy
  ]
}

resource "aws_s3_bucket_versioning" "customer_inventory_bucket" {
  count = local.enable_org_inv_mgmt_customer ? 1 : 0
  bucket = aws_s3_bucket.customer_inventory_bucket[0].id
  versioning_configuration {
    status = var.xosphere_customer_inventory_enable_versioning ? "Enabled" : "Disabled"
  }
}

resource "aws_s3_bucket_policy" "customer_inventory_bucket" {
  count = local.enable_org_inv_mgmt_customer ? 1 : 0
  bucket = aws_s3_bucket.customer_inventory_bucket[0].id
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "s3:ListBucket",
        "s3:ListBucketVersions"
      ],
      "Effect": "Allow",
      "Resource": "${aws_s3_bucket.customer_inventory_bucket[0].arn}",
      "Principal": {
        "AWS": "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
      }
    },
    {
      "Action": "s3:GetObject",
      "Effect": "Allow",
      "Resource": "${aws_s3_bucket.customer_inventory_bucket[0].arn}/*",
      "Principal": "*",
      "Condition": {
        "StringEquals": {
          "aws:PrincipalOrgID": "${var.aws_organization_id}" %{ if false } # should use a pseudo parameter, but AWS doesn't yet provide one.  https://github.com/aws-cloudformation/cloudformation-coverage-roadmap/issues/160 %{ endif }
        }
%{ if var.enable_enhanced_security }        
        ,
        "ArnLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/xosphere-*"
        }
%{ endif }
      }
    }      

%{ if var.xosphere_customer_inventory_replication_role_arn != "" }
    ,
    {
      "Sid": "Customer Replication: Permissions on objects",
      "Action": [
        "s3:ReplicateDelete",
        "s3:ReplicateObject",
        "s3:ReplicateTags",
        "s3:ObjectOwnerOverrideToBucketOwner"
      ],
      "Effect": "Allow",
      "Resource": "${aws_s3_bucket.customer_inventory_bucket[0].arn}/*",
      "Principal": {
        "AWS": "${var.xosphere_customer_inventory_replication_role_arn}"
      }
    }
%{ endif }
%{ if var.xosphere_customer_inventory_replication_role_arn != "" }
    ,
    {
      "Sid": "Replication: Permissions on bucket",
      "Action": [
        "s3:List*",
        "s3:GetBucketVersioning",
        "s3:PutBucketVersioning"
      ],
      "Effect": "Allow",
      "Resource": "${aws_s3_bucket.customer_inventory_bucket[0].arn}",
      "Principal": {
        "AWS": "${var.xosphere_customer_inventory_replication_role_arn}"
      }
    }
%{ endif }
  ]
}
EOF
}

resource "aws_lambda_function" "xosphere_organization_ri_data_gatherer_lambda_function" {
  s3_bucket = local.s3_bucket
  s3_key = "org/ri-data-gatherer-lambda-${local.version}.zip"
  description = "Xosphere AWS Organization RI Data Gatherer"
  environment {
    variables = {
      ORGANIZATION_DATA_S3_BUCKET = aws_s3_bucket.organization_data_bucket.id
      ORGANIZATION_RI_DATA_MERGER_SQS_QUEUE_URL = aws_sqs_queue.xosphere_organization_ri_data_merger_queue.url
      AWS_ORGANIZATION_MGMT_ACCOUNT_ID= var.aws_organization_mgmt_account_id
    }
  }
  function_name = local.lambda_function_map_xosphere_organization_ri_data_gatherer
  handler = "ri-data-gatherer"
  memory_size = 1024
  role = aws_iam_role.xosphere_organization_ri_data_gatherer_lambda_role.arn
  runtime = "go1.x"
  timeout = 900
  depends_on = [ aws_cloudwatch_log_group.xosphere_organization_ri_data_gatherer_log_group ]
}

resource "aws_iam_role" "xosphere_organization_ri_data_gatherer_lambda_role" {
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": {
    "Action": [ "sts:AssumeRole" ],
    "Effect": "Allow",
    "Principal": {
      "Service": [ "lambda.amazonaws.com" ]
    }
  }
}
EOF
  managed_policy_arns = [ ]
  path = "/"
  name = "${local.lambda_function_map_xosphere_organization_ri_data_gatherer}-lambda-role"
}

resource "aws_iam_role_policy" "xosphere_organization_ri_data_gatherer_lambda_role_policy" {
  name = "${local.lambda_function_map_xosphere_organization_ri_data_gatherer}-lambda-policy"
  role = aws_iam_role.xosphere_organization_ri_data_gatherer_lambda_role.id
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowLogOperationsOnXosphereLogGroups",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
	    ],
      "Resource": [
        "arn:aws:logs:*:*:log-group:/aws/lambda/xosphere-*",
        "arn:aws:logs:*:*:log-group:/aws/lambda/xosphere-*:log-stream:*"
      ]
    },
    {
      "Sid": "AllowS3OperationsOnXosphereObjects",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:GetObjectVersion",
        "s3:GetObjectVersionTagging",
        "s3:PutObject",
        "s3:PutObjectTagging",
        "s3:PutObjectVersionTagging"
	    ],
      "Resource": "arn:aws:s3:::xosphere-*/*"
    },
    {
      "Sid": "AllowS3OperationsOnXosphereBuckets",
      "Effect": "Allow",
      "Action": [
        "s3:ListBucket",
        "s3:ListBucketVersions"
	    ],
      "Resource": "arn:aws:s3:::xosphere-*"
    },
    {
      "Sid": "AllowSecretManagerOperations",
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue"
	    ],
      "Resource": "${local.api_token_arn}"
    },
    {
      "Sid": "AllowKmsOperations",
      "Effect": "Allow",
      "Action": [
        "kms:Decrypt"
	    ],
      "Resource": "${local.kms_key_pattern}"
    },
    {
      "Sid": "AssumeOrgRole",
      "Effect": "Allow",
      "Action": [
        "sts:AssumeRole"
	    ],
      "Resource": "arn:aws:iam::${var.aws_organization_mgmt_account_id}:role/${local.lambda_function_map_xosphere_organization_ri_data_gatherer}-lambda-assume-role"
    },
    {
      "Sid": "AllowOrgKmsOperations",
      "Effect": "Allow",
      "Action": [
        "kms:Decrypt",
        "kms:GenerateDataKey"
	    ],
      "Resource": "${aws_kms_key.xosphere_mgmt_cmk.arn}"
    },
    {
      "Sid": "AllowPublishMergerSqs",
      "Effect": "Allow",
      "Action": [
        "sqs:SendMessage"
	    ],
      "Resource": "${aws_sqs_queue.xosphere_organization_ri_data_merger_queue.arn}"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "xosphere_organization_ri_data_gatherer_lambda_role_policy_service_linked_roles" {
  name = "${local.lambda_function_map_xosphere_organization_ri_data_gatherer}-lambda-policy-service-linked-roles"
  role = aws_iam_role.xosphere_organization_ri_data_gatherer_lambda_role.id
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowLambdaServiceLinkedRole",
      "Effect": "Allow",
      "Action": [
        "iam:CreateServiceLinkedRole"
	    ],
      "Resource": [
        "arn:aws:iam::*:role/aws-service-role/lambda.amazonaws.com/*"
      ],
      "Condition": {
        "StringLike": {
          "iam:AWSServiceName": [
            "lambda.amazonaws.com"
          ]
        }
      }
    },
    {
      "Sid": "AllowLambdaServiceLinkedRolePolicies",
      "Effect": "Allow",
      "Action": [
        "iam:AttachRolePolicy",
        "iam:PutRolePolicy"
	    ],
      "Resource": "arn:aws:iam::*:role/aws-service-role/lambda.amazonaws.com/*"
    }
  ]
}
EOF
}

resource "aws_cloudwatch_log_group" "xosphere_organization_ri_data_gatherer_log_group" {
  name = "/aws/lambda/${local.lambda_function_map_xosphere_organization_ri_data_gatherer}"
  retention_in_days = 30
}

resource "aws_lambda_permission" "xosphere_organization_ri_data_gatherer_lambda_permission" {
  action = "lambda:InvokeFunction"
  function_name = aws_lambda_function.xosphere_organization_ri_data_gatherer_lambda_function.arn
  principal = "events.amazonaws.com"
  source_arn = aws_cloudwatch_event_rule.xosphere_organization_ri_data_gatherer_schedule.arn
}

resource "aws_cloudwatch_event_rule" "xosphere_organization_ri_data_gatherer_schedule" {
  name = "${local.lambda_function_map_xosphere_organization_ri_data_gatherer}-schedule-event-rule"
  description = "Schedule for launching Xosphere AWS Organization RI Data Gatherer"
  schedule_expression = "cron(${var.organization_ri_data_gatherer_schedule_expression})"
  is_enabled = true
}

resource "aws_cloudwatch_event_target" "xosphere_organization_ri_data_gatherer_schedule_target" {
  arn = aws_lambda_function.xosphere_organization_ri_data_gatherer_lambda_function.arn
  rule = aws_cloudwatch_event_rule.xosphere_organization_ri_data_gatherer_schedule.name
  target_id = "${local.lambda_function_map_xosphere_organization_ri_data_gatherer}-schedule"
}

resource "aws_lambda_function" "xosphere_organization_inventory_data_processor_lambda_function" {
  s3_bucket = local.s3_bucket
  s3_key = "org/inv-data-processor-lambda-${local.version}.zip"
  description = "Xosphere AWS Organization Inventory Data Processor"
  environment {
    variables = {
      ORGANIZATION_DATA_S3_BUCKET = aws_s3_bucket.organization_data_bucket.id
    }
  }
  function_name = local.lambda_function_map_xosphere_organization_inventory_data_processor
  handler = "inv-data-processor"
  memory_size = 256
  role = aws_iam_role.xosphere_organization_inventory_data_processor_lambda_role.arn
  runtime = "go1.x"
  timeout = 300
  reserved_concurrent_executions = 1
  depends_on = [ aws_cloudwatch_log_group.xosphere_organization_inventory_data_processor_log_group ]
}

resource "aws_iam_role" "xosphere_organization_inventory_data_processor_lambda_role" {
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": {
    "Action": [ "sts:AssumeRole" ],
    "Effect": "Allow",
    "Principal": {
      "Service": [ "lambda.amazonaws.com" ]
    }
  }
}
EOF
  managed_policy_arns = [ ]
  path = "/"
  name = "${local.lambda_function_map_xosphere_organization_inventory_data_processor}-lambda-role"
}

resource "aws_iam_role_policy" "xosphere_organization_inventory_data_processor_lambda_role_policy" {
  name = "${local.lambda_function_map_xosphere_organization_inventory_data_processor}-lambda-policy"
  role = aws_iam_role.xosphere_organization_inventory_data_processor_lambda_role.id
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowLogOperationsOnXosphereLogGroups",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
	    ],
      "Resource": [
        "arn:aws:logs:*:*:log-group:/aws/lambda/xosphere-*",
        "arn:aws:logs:*:*:log-group:/aws/lambda/xosphere-*:log-stream:*"
      ]
    },
    {
      "Sid": "AllowS3OperationsOnXosphereObjects",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:GetObjectVersion",
        "s3:GetObjectVersionTagging",
        "s3:PutObject",
        "s3:PutObjectTagging",
        "s3:PutObjectVersionTagging",
        "s3:DeleteObject"
	    ],
      "Resource": "arn:aws:s3:::xosphere-*/*"
    },
    {
      "Sid": "AllowS3OperationsOnXosphereBuckets",
      "Effect": "Allow",
      "Action": [
        "s3:ListBucket",
        "s3:ListBucketVersions"
	    ],
      "Resource": "arn:aws:s3:::xosphere-*"
    },
    {
      "Sid": "AllowInvUpdateReadSqs",
      "Effect": "Allow",
      "Action": [
        "sqs:ChangeMessageVisibility",
        "sqs:DeleteMessage",
        "sqs:GetQueueAttributes",
        "sqs:ReceiveMessage",
        "sqs:GetQueueUrl"
	    ],
      "Resource": "${aws_sqs_queue.xosphere_organization_inventory_data_processor_queue.arn}"
    },
    {
      "Sid": "AllowSecretManagerOperations",
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue"
	    ],
      "Resource": "${local.api_token_arn}"
    },
    {
      "Sid": "AllowKmsOperations",
      "Effect": "Allow",
      "Action": [
        "kms:Decrypt"
	    ],
      "Resource": "${local.kms_key_pattern}"
    },
    {
      "Sid": "AllowOrgKmsOperations",
      "Effect": "Allow",
      "Action": [
        "kms:Decrypt"
	    ],
      "Resource": "${aws_kms_key.xosphere_mgmt_cmk.arn}"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "xosphere_organization_inventory_data_processor_lambda_role_policy_service_linked_roles" {
  name = "${local.lambda_function_map_xosphere_organization_inventory_data_processor}-lambda-policy-service-linked-roles"
  role = aws_iam_role.xosphere_organization_inventory_data_processor_lambda_role.id
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowLambdaServiceLinkedRole",
      "Effect": "Allow",
      "Action": [
        "iam:CreateServiceLinkedRole"
	    ],
      "Resource": [
        "arn:aws:iam::*:role/aws-service-role/lambda.amazonaws.com/*"
      ],
      "Condition": {
        "StringLike": {
          "iam:AWSServiceName": [
            "lambda.amazonaws.com"
          ]
        }
      }
    },
    {
      "Sid": "AllowLambdaServiceLinkedRolePolicies",
      "Effect": "Allow",
      "Action": [
        "iam:AttachRolePolicy",
        "iam:PutRolePolicy"
	    ],
      "Resource": "arn:aws:iam::*:role/aws-service-role/lambda.amazonaws.com/*"
    }
  ]
}
EOF
}

resource "aws_cloudwatch_log_group" "xosphere_organization_inventory_data_processor_log_group" {
  name = "/aws/lambda/${local.lambda_function_map_xosphere_organization_inventory_data_processor}"
  retention_in_days = 30
}

resource "aws_lambda_permission" "xosphere_organization_inventory_data_processor_lambda_permission_scheduler" {
  action = "lambda:InvokeFunction"
  function_name = aws_lambda_function.xosphere_organization_inventory_data_processor_lambda_function.arn
  principal = "events.amazonaws.com"
  source_arn = aws_cloudwatch_event_rule.xosphere_organization_inventory_data_processor_schedule.arn
}

resource "aws_lambda_permission" "xosphere_organization_inventory_data_processor_lambda_permission_queue" {
  action = "lambda:InvokeFunction"
  function_name = aws_lambda_function.xosphere_organization_inventory_data_processor_lambda_function.arn
  principal = "sqs.amazonaws.com"
  source_arn = aws_sqs_queue.xosphere_organization_inventory_data_processor_queue.arn
}

resource "aws_cloudwatch_event_rule" "xosphere_organization_inventory_data_processor_schedule" {
  name = "${local.lambda_function_map_xosphere_organization_inventory_data_processor}-schedule-event-rule"
  description = "Schedule for launching Xosphere AWS Organization Inventory Data Processor"
  schedule_expression = "cron(${var.organization_inventory_data_processor_schedule_expression})"
  is_enabled = true
}

resource "aws_cloudwatch_event_target" "xosphere_organization_inventory_data_processor_schedule_target" {
  arn = aws_lambda_function.xosphere_organization_inventory_data_processor_lambda_function.arn
  rule = aws_cloudwatch_event_rule.xosphere_organization_inventory_data_processor_schedule.name
  target_id = "${local.lambda_function_map_xosphere_organization_inventory_data_processor}-schedule"
}

resource "aws_lambda_event_source_mapping" "xosphere_organization_inventory_data_processor_event_source_mapping" {
  batch_size = 50
  maximum_batching_window_in_seconds = 10
  enabled = true
  event_source_arn = aws_sqs_queue.xosphere_organization_inventory_data_processor_queue.arn
  function_name = aws_lambda_function.xosphere_organization_inventory_data_processor_lambda_function.arn
  depends_on = [ aws_iam_role.xosphere_organization_inventory_data_processor_lambda_role ]
}

resource "aws_sqs_queue" "xosphere_organization_inventory_data_processor_queue" {
  name = "xosphere-instance-orchestrator-org-inv-data-processor-launch"
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.xosphere_organization_inventory_data_processor_dl_queue.arn
    maxReceiveCount = 5
  })
  visibility_timeout_seconds = 1020
  kms_master_key_id = aws_kms_key.xosphere_mgmt_cmk.id
}

resource "aws_sqs_queue_policy" "xosphere_organization_inventory_data_processor_queue_policy" {
  queue_url = aws_sqs_queue.xosphere_organization_inventory_data_processor_queue.id

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowSendSqsUpdates",
      "Effect": "Allow",
      "Principal": {
        "AWS": "${aws_iam_role.xosphere_organization_instance_state_event_collector_lambda_role.arn}"
      },
      "Action": "sqs:SendMessage",
      "Resource": "${aws_sqs_queue.xosphere_organization_inventory_data_processor_queue.arn}"
    }
%{ if local.enable_org_inv_mgmt_customer }
    ,{
      "Sid": "AllowSendSqsUpdatesCustomerParser",
      "Effect": "Allow",
      "Principal": {
        "AWS": "${aws_iam_role.xosphere_organization_inventory_customer_parser_lambda_role[0].arn}"
      },
      "Action": "sqs:SendMessage",
      "Resource": "${aws_sqs_queue.xosphere_organization_inventory_data_processor_queue.arn}"
    }
%{ endif }
%{ if local.enable_org_inv_mgmt_xosphere }
    ,{
      "Sid": "AllowSendSqsUpdatesInvBaselineMerger",
      "Effect": "Allow",
      "Principal": {
        "AWS": "${aws_iam_role.xosphere_organization_inventory_baseline_merger_lambda_role[0].arn}"
      },
      "Action": "sqs:SendMessage",
      "Resource": "${aws_sqs_queue.xosphere_organization_inventory_data_processor_queue.arn}"
    }
%{ endif }
  ]
}
EOF
}

resource "aws_sqs_queue" "xosphere_organization_inventory_data_processor_dl_queue" {
  name = "xosphere-instance-orchestrator-org-inv-data-processor-launch-dlq"
  visibility_timeout_seconds = 1020
  kms_master_key_id = aws_kms_key.xosphere_mgmt_cmk.id
}

resource "aws_sqs_queue" "xosphere_organization_ri_sub_account_submission_queue" {
  name = "xosphere-instance-orchestrator-org-ri-sub-acct-submissions"
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.xosphere_organization_ri_sub_account_submission_dl_queue.arn
    maxReceiveCount = 5
  })

  visibility_timeout_seconds = 1020
  kms_master_key_id = aws_kms_key.xosphere_mgmt_cmk.id
  kms_data_key_reuse_period_seconds = 300
}

resource "aws_sqs_queue_policy" "xosphere_organization_ri_sub_account_submission_queue_policy" {
  queue_url = aws_sqs_queue.xosphere_organization_ri_sub_account_submission_queue.id

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowSendSqsUpdates",
      "Effect": "Allow",
      "Principal": {
        "AWS": "*"
      },
      "Action": "sqs:SendMessage",
      "Resource": "${aws_sqs_queue.xosphere_organization_ri_sub_account_submission_queue.arn}",
      "Condition": {
        "StringEquals": {
          "aws:PrincipalOrgID": "${var.aws_organization_id}" %{ if false } # should use a pseudo parameter, but AWS doesn't yet provide one.  https://github.com/aws-cloudformation/cloudformation-coverage-roadmap/issues/160 %{ endif }
        }
%{ if var.enable_enhanced_security }        
        ,
        "ArnLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/${local.lambda_function_map_xosphere_organization_ri_sub_account_reporter}-lambda-role"
        }
%{ endif }
      }
    }    
  ]
}
EOF
}

resource "aws_sqs_queue" "xosphere_organization_ri_data_merger_queue" {
  name = "xosphere-instance-orchestrator-org-ri-data-merger"
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.xosphere_organization_ri_data_merger_dl_queue.arn
    maxReceiveCount = 5
  })

  visibility_timeout_seconds = 1020
  kms_master_key_id = aws_kms_key.xosphere_mgmt_cmk.id
  kms_data_key_reuse_period_seconds = 300
}

resource "aws_sqs_queue" "xosphere_organization_ri_data_merger_dl_queue" {
  name = "xosphere-instance-orchestrator-org-ri-data-merger-dlq"
  visibility_timeout_seconds = 1020
  kms_master_key_id = aws_kms_key.xosphere_mgmt_cmk.id
  kms_data_key_reuse_period_seconds = 300
}

resource "aws_kms_key" "xosphere_mgmt_cmk" {
  description = "Encryption key for organization RI sub-account submissions"
  enable_key_rotation = true
  deletion_window_in_days = 20
  policy = <<EOF
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "Delegate permission to root user",
        "Effect": "Allow",
        "Principal": {
          "AWS": "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        },
        "Action": "kms:*",
        "Resource": "*" %{ if false } # '*' here means "this kms key" https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-overview.html %{ endif }
      },
      {
        "Sid": "Delegate permission to sub-account",
        "Effect": "Allow",
        "Principal": {
          "AWS": "*"
        },
        "Action": [ "kms:Decrypt", "kms:GenerateDataKey" ],
        "Resource": "*", %{ if false } # '*' here means "this kms key" https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-overview.html %{ endif }
        "Condition": {
          "StringEquals": {
            "aws:PrincipalOrgID": "${var.aws_organization_id}" %{ if false } # should use a pseudo parameter, but AWS doesn't yet provide one.  https://github.com/aws-cloudformation/cloudformation-coverage-roadmap/issues/160 %{ endif }
          }
  %{ if var.enable_enhanced_security }        
          ,
          "ArnLike": {
            "aws:PrincipalArn": "arn:aws:iam::*:role/xosphere-*-lambda-role"
          }
  %{ endif }
        }
      },
      {
        "Sid": "AllowS3Notifications",
        "Effect": "Allow",
        "Principal": {
          "Service": "s3.amazonaws.com"
        },
        "Action": [ "kms:Decrypt", "kms:GenerateDataKey" ],
        "Resource": "*", %{ if false } # '*' here means "this kms key" https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-overview.html %{ endif }
        "Condition": {
          "StringEquals": {
            "aws:SourceAccount": "${data.aws_caller_identity.current.account_id}"
          }
        }
      },
  %{ if var.xosphere_customer_inventory_replication_role_arn != "" }
      {
        "Sid": "Delegate permissions to customer account replication",
        "Effect": "Allow",
        "Principal": {
          "AWS": "${var.xosphere_customer_inventory_replication_role_arn}"
        },
        "Action": [ "kms:Encrypt", "kms:GenerateDataKey" ],
        "Resource": "*" %{ if false } # '*' here means "this kms key" https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-overview.html %{ endif }
      },
  %{ endif }
  %{ if local.enable_org_inv_mgmt_xosphere }
      {
        "Sid": "AllowEventBridgeEvents",
        "Effect": "Allow",
        "Principal": {
          "Service": "events.amazonaws.com"
        },
        "Action": [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ],
        "Resource": "*", %{ if false } # '*' here means "this kms key" https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-overview.html %{ endif }
        "Condition": {
          "StringEquals": {
            "aws:SourceAccount": "${data.aws_caller_identity.current.account_id}"
          }
        }
      },
  %{ endif }
      {
        "Sid": "S3 Access logging",
        "Effect": "Allow",
        "Principal": {
          "Service": "logging.s3.amazonaws.com"
        },
        "Action": "kms:*",
        "Resource": "*" %{ if false } # '*' here means "this kms key" https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-overview.html %{ endif }
      }
    ]
  }
EOF

  # TODO
  # tags = "${merge(
  #   local.enable_xosphere_customer_inventory_cmk_tag ? 
  #   map(
  #     "${var.xosphere_customer_inventory_cmk_custom_tag_name}", var.xosphere_customer_inventory_cmk_custom_tag_value
  #   ) :
  #   map()
  # )}"
}

resource "aws_kms_alias" "xosphere_mgmt_cmk_alias" {
  name          = "alias/XosphereMgmtCmk"
  target_key_id = aws_kms_key.xosphere_mgmt_cmk.key_id
}

resource "aws_sqs_queue" "xosphere_organization_ri_sub_account_submission_dl_queue" {
  name = "xosphere-instance-orchestrator-org-ri-sub-acct-submissions-dlq"
  visibility_timeout_seconds = 1020
  kms_master_key_id = aws_kms_key.xosphere_mgmt_cmk.id
  kms_data_key_reuse_period_seconds = 300
}

resource "aws_iam_role" "xosphere_organization_ri_sub_account_submission_processor_role" {
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": {
    "Action": [ "sts:AssumeRole" ],
    "Effect": "Allow",
    "Principal": {
      "Service": [ "lambda.amazonaws.com" ]
    }
  }
}
EOF
  managed_policy_arns = [ ]
  path = "/"
  name = "${local.lambda_function_map_xosphere_organization_ri_sub_account_submission_processor}-lambda-role"
}

resource "aws_iam_role_policy" "xosphere_organization_ri_sub_account_submission_processor_role_policy" {
  name = "${local.lambda_function_map_xosphere_organization_ri_sub_account_submission_processor}-lambda-policy"
  role = aws_iam_role.xosphere_organization_ri_sub_account_submission_processor_role.id
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowLogOperationsOnXosphereLogGroups",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
	    ],
      "Resource": [
        "arn:aws:logs:*:*:log-group:/aws/lambda/xosphere-*",
        "arn:aws:logs:*:*:log-group:/aws/lambda/xosphere-*:log-stream:*"
      ]
    },
    {
      "Sid": "AllowS3OperationsOnXosphereObjects",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:GetObjectVersion",
        "s3:GetObjectVersionTagging",
        "s3:PutObject",
        "s3:PutObjectTagging",
        "s3:PutObjectVersionTagging"
	    ],
      "Resource": "arn:aws:s3:::xosphere-*/*"
    },
    {
      "Sid": "AllowS3OperationsOnXosphereBuckets",
      "Effect": "Allow",
      "Action": [
        "s3:ListBucket",
        "s3:ListBucketVersions"
	    ],
      "Resource": "arn:aws:s3:::xosphere-*"
    },
    {
      "Sid": "AllowSubAcctS3",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:GetObjectVersion",
        "s3:GetObjectVersionTagging"
	    ],
      "Resource": "*",
      "Condition": {
        "StringLike": {
          "aws:ResourceTag/xosphere.io/instance-orchestrator/is-org-ri-sub-account-bucket": [ "true" ]
        }
      }
    },
    {
      "Sid": "AllowSecretManagerOperations",
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue"
	    ],
      "Resource": "${local.api_token_arn}"
    },
    {
      "Sid": "AllowKmsOperations",
      "Effect": "Allow",
      "Action": [
        "kms:Decrypt"
	    ],
      "Resource": "${local.kms_key_pattern}"
    },
    {
      "Sid": "AllowOrgKmsOperations",
      "Effect": "Allow",
      "Action": [
        "kms:Decrypt",
        "kms:GenerateDataKey"
	    ],
      "Resource": "${aws_kms_key.xosphere_mgmt_cmk.arn}"
    },
    {
      "Sid": "AllowOrgReadSqs",
      "Effect": "Allow",
      "Action": [
        "sqs:ChangeMessageVisibility",
        "sqs:DeleteMessage",
        "sqs:GetQueueAttributes",
        "sqs:ReceiveMessage",
        "sqs:GetQueueUrl"
	    ],
      "Resource": "${aws_sqs_queue.xosphere_organization_ri_sub_account_submission_queue.arn}"
    },
    {
      "Sid": "AllowPublishMergerSqs",
      "Effect": "Allow",
      "Action": [
        "sqs:SendMessage"
	    ],
      "Resource": "${aws_sqs_queue.xosphere_organization_ri_data_merger_queue.arn}"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "xosphere_organization_ri_sub_account_submission_processor_role_policy_service_linked_roles" {
  name = "${local.lambda_function_map_xosphere_organization_ri_sub_account_submission_processor}-lambda-policy-service-linked-roles"
  role = aws_iam_role.xosphere_organization_ri_sub_account_submission_processor_role.id
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowLambdaServiceLinkedRole",
      "Effect": "Allow",
      "Action": [
        "iam:CreateServiceLinkedRole"
	    ],
      "Resource": [
        "arn:aws:iam::*:role/aws-service-role/lambda.amazonaws.com/*"
      ],
      "Condition": {
        "StringLike": {
          "iam:AWSServiceName": [
            "lambda.amazonaws.com"
          ]
        }
      }
    },
    {
      "Sid": "AllowLambdaServiceLinkedRolePolicies",
      "Effect": "Allow",
      "Action": [
        "iam:AttachRolePolicy",
        "iam:PutRolePolicy"
	    ],
      "Resource": "arn:aws:iam::*:role/aws-service-role/lambda.amazonaws.com/*"
    }
  ]
}
EOF
}

resource "aws_lambda_event_source_mapping" "xosphere_organization_ri_sub_account_submission_processor_event_source_mapping" {
  batch_size = 50
  maximum_batching_window_in_seconds = 30
  enabled = true
  event_source_arn = aws_sqs_queue.xosphere_organization_ri_sub_account_submission_queue.arn
  function_name = aws_lambda_function.xosphere_organization_ri_sub_account_submission_processor_lambda_function.arn
  depends_on = [ aws_iam_role.xosphere_organization_ri_sub_account_submission_processor_role ]
}

resource "aws_lambda_permission" "xosphere_organization_ri_sub_account_submission_processor_lambda_permission" {
  action = "lambda:InvokeFunction"
  function_name = aws_lambda_function.xosphere_organization_ri_sub_account_submission_processor_lambda_function.arn
  principal = "sqs.amazonaws.com"
  source_arn = aws_sqs_queue.xosphere_organization_ri_sub_account_submission_queue.arn
}

resource "aws_cloudwatch_log_group" "xosphere_organization_ri_sub_account_submission_processor_log_group" {
  name = "/aws/lambda/${local.lambda_function_map_xosphere_organization_ri_sub_account_submission_processor}"
  retention_in_days = 30
}

resource "aws_lambda_function" "xosphere_organization_ri_sub_account_submission_processor_lambda_function" {
  s3_bucket = local.s3_bucket
  s3_key = "org/ri-sub-acct-processor-lambda-${local.version}.zip"
  description = "Xosphere Organization RI sub-account processor"
  environment {
    variables = {
      API_TOKEN_ARN = local.api_token_arn
      ENDPOINT_URL = local.endpoints_map_xosphere_api_endpoint
      SQS_QUEUE = aws_sqs_queue.xosphere_organization_ri_sub_account_submission_queue.url
      ORGANIZATION_DATA_S3_BUCKET = aws_s3_bucket.organization_data_bucket.id
      ORGANIZATION_RI_DATA_MERGER_SQS_QUEUE_URL = aws_sqs_queue.xosphere_organization_ri_data_merger_queue.url
    }
  }
  function_name = local.lambda_function_map_xosphere_organization_ri_sub_account_submission_processor
  handler = "ri-sub-acct-processor"
  memory_size = 256
  role = aws_iam_role.xosphere_organization_ri_sub_account_submission_processor_role.arn
  runtime = "go1.x"
  timeout = 900
  depends_on = [ aws_cloudwatch_log_group.xosphere_organization_ri_sub_account_submission_processor_log_group ]
}

resource "aws_lambda_function" "xosphere_organization_ri_data_merger_lambda_function" {
  s3_bucket = local.s3_bucket
  s3_key = "org/ri-data-merger-lambda-${local.version}.zip"
  description = "Xosphere AWS Organization RI Data Merger"
  environment {
    variables = {
      ORGANIZATION_DATA_S3_BUCKET = aws_s3_bucket.organization_data_bucket.id
      ORGANIZATION_RI_PURCHASING_ACCOUNTS = join(",", var.ri_purchasing_accounts)
    }
  }
  function_name = local.lambda_function_map_xosphere_organization_ri_data_merger
  handler = "ri-data-merger"
  memory_size = 1024
  role = aws_iam_role.xosphere_organization_ri_data_merger_lambda_role.arn
  runtime = "go1.x"
  timeout = 900
  reserved_concurrent_executions = 1
  depends_on = [ aws_cloudwatch_log_group.xosphere_organization_ri_data_merger_log_group ]
}

resource "aws_iam_role" "xosphere_organization_ri_data_merger_lambda_role" {
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": {
    "Action": [ "sts:AssumeRole" ],
    "Effect": "Allow",
    "Principal": {
      "Service": [ "lambda.amazonaws.com" ]
    }
  }
}
EOF
  managed_policy_arns = [ ]
  path = "/"
  name = "${local.lambda_function_map_xosphere_organization_ri_data_merger}-lambda-role"
}

resource "aws_iam_role_policy" "xosphere_organization_ri_data_merger_lambda_role_policy" {
  name = "${local.lambda_function_map_xosphere_organization_ri_data_merger}-lambda-policy"
  role = aws_iam_role.xosphere_organization_ri_data_merger_lambda_role.id
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowLogOperationsOnXosphereLogGroups",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
	    ],
      "Resource": [
        "arn:aws:logs:*:*:log-group:/aws/lambda/xosphere-*",
        "arn:aws:logs:*:*:log-group:/aws/lambda/xosphere-*:log-stream:*"
      ]
    },
    {
      "Sid": "AllowS3OperationsOnXosphereObjects",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:GetObjectVersion",
        "s3:GetObjectVersionTagging",
        "s3:PutObject",
        "s3:PutObjectTagging",
        "s3:PutObjectVersionTagging"
	    ],
      "Resource": "arn:aws:s3:::xosphere-*/*"
    },   
    {
      "Sid": "AllowS3OperationsOnXosphereBuckets",
      "Effect": "Allow",
      "Action": [
        "s3:ListBucket",
        "s3:ListBucketVersions"
	    ],
      "Resource": "arn:aws:s3:::xosphere-*"
    },   
    {
      "Sid": "AllowSecretManagerOperations",
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue"
	    ],
      "Resource": "${local.api_token_arn}"
    },   
    {
      "Sid": "AllowKmsOperations",
      "Effect": "Allow",
      "Action": [
        "kms:Decrypt"
	    ],
      "Resource": "${local.kms_key_pattern}"
    },   
    {
      "Sid": "AllowOrgReadSqs",
      "Effect": "Allow",
      "Action": [
        "sqs:ChangeMessageVisibility",
        "sqs:DeleteMessage",
        "sqs:GetQueueAttributes",
        "sqs:ReceiveMessage",
        "sqs:GetQueueUrl"
	    ],
      "Resource": "${aws_sqs_queue.xosphere_organization_ri_data_merger_queue.arn}"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "xosphere_organization_ri_data_merger_lambda_role_policy_service_linked_roles" {
  name = "${local.lambda_function_map_xosphere_organization_ri_data_merger}-lambda-policy-service-linked-roles"
  role = aws_iam_role.xosphere_organization_ri_data_merger_lambda_role.id
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowLambdaServiceLinkedRole",
      "Effect": "Allow",
      "Action": [
        "iam:CreateServiceLinkedRole"
	    ],
      "Resource": [
        "arn:aws:iam::*:role/aws-service-role/lambda.amazonaws.com/*"
      ],
      "Condition": {
        "StringLike": {
          "iam:AWSServiceName": [
            "lambda.amazonaws.com"
          ]
        }
      }
    },
    {
      "Sid": "AllowLambdaServiceLinkedRolePolicies",
      "Effect": "Allow",
      "Action": [
        "iam:AttachRolePolicy",
        "iam:PutRolePolicy"
	    ],
      "Resource": "arn:aws:iam::*:role/aws-service-role/lambda.amazonaws.com/*"
    }
  ]
}
EOF
}

resource "aws_cloudwatch_log_group" "xosphere_organization_ri_data_merger_log_group" {
  name = "/aws/lambda/${local.lambda_function_map_xosphere_organization_ri_data_merger}"
  retention_in_days = 30
}

resource "aws_lambda_permission" "xosphere_organization_ri_data_merger_lambda_permission" {
  action = "lambda:InvokeFunction"
  function_name = aws_lambda_function.xosphere_organization_ri_data_merger_lambda_function.arn
  principal = "sqs.amazonaws.com"
  source_arn = aws_sqs_queue.xosphere_organization_ri_data_merger_queue.arn
}

resource "aws_lambda_event_source_mapping" "xosphere_organization_ri_data_merger_event_source_mapping" {
  batch_size = 500
  maximum_batching_window_in_seconds = 60
  enabled = true
  event_source_arn = aws_sqs_queue.xosphere_organization_ri_data_merger_queue.arn
  function_name = aws_lambda_function.xosphere_organization_ri_data_merger_lambda_function.arn
  depends_on = [ aws_iam_role.xosphere_organization_ri_data_merger_lambda_role ]
}

resource "aws_iam_role" "xosphere_organization_ri_sub_account_reporter_role" {
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": {
    "Action": [ "sts:AssumeRole" ],
    "Effect": "Allow",
    "Principal": {
      "Service": [ "lambda.amazonaws.com" ]
    }
  }
}
EOF
  managed_policy_arns = [ ]
  path = "/"
  name = "${local.lambda_function_map_xosphere_organization_ri_sub_account_reporter}-lambda-role"
}

resource "aws_iam_role_policy" "xosphere_organization_ri_sub_account_reporter_role_policy" {
  name = "${local.lambda_function_map_xosphere_organization_ri_sub_account_reporter}-lambda-policy"
  role = aws_iam_role.xosphere_organization_ri_sub_account_reporter_role.id
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowOperationsWithoutResourceRestrictions",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeRegions",
        "ec2:DescribeReservedInstances"
	    ],
      "Resource": "*"
    },  
    {
      "Sid": "AllowLogOperationsOnXosphereLogGroups",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
	    ],
      "Resource": [
        "arn:aws:logs:*:*:log-group:/aws/lambda/xosphere-*",
        "arn:aws:logs:*:*:log-group:/aws/lambda/xosphere-*:log-stream:*"
      ]
    },  
    {
      "Sid": "AllowS3OperationsOnXosphereObjects",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:GetObjectVersion",
        "s3:GetObjectVersionTagging",
        "s3:PutObject",
        "s3:PutObjectTagging",
        "s3:PutObjectVersionTagging"
	    ],
      "Resource": "arn:aws:s3:::xosphere-*/*"
    },  
    {
      "Sid": "AllowS3OperationsOnXosphereBuckets",
      "Effect": "Allow",
      "Action": [
        "s3:ListBucket",
        "s3:ListBucketVersions"
	    ],
      "Resource": "arn:aws:s3:::xosphere-*"
    },
    {
      "Sid": "AllowSecretManagerOperations",
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue"
	    ],
      "Resource": "${local.api_token_arn}"
    },
    {
      "Sid": "AllowKmsOperations",
      "Effect": "Allow",
      "Action": [
        "kms:Decrypt"
	    ],
      "Resource": "${local.kms_key_pattern}"
    },
    {
      "Sid": "AllowOrgKmsOperations",
      "Effect": "Allow",
      "Action": [
        "kms:Decrypt",
        "kms:GenerateDataKey"
	    ],
      "Resource": "${aws_kms_key.xosphere_mgmt_cmk.arn}"
    },
    {
      "Sid": "AllowOrgPublishSqs",
      "Effect": "Allow",
      "Action": [
        "sqs:SendMessage"
	    ],
      "Resource": "${aws_sqs_queue.xosphere_organization_ri_sub_account_submission_queue.arn}"
    },
    {
      "Sid": "AllowOrgReadSqs",
      "Effect": "Allow",
      "Action": [
        "sqs:ChangeMessageVisibility",
        "sqs:DeleteMessage",
        "sqs:GetQueueAttributes",
        "sqs:ReceiveMessage",
        "sqs:GetQueueUrl"
	    ],
      "Resource": "${aws_sqs_queue.xosphere_organization_ri_sub_account_request_queue.arn}"
    },
    {
      "Sid": "AssumeOrgRole",
      "Effect": "Allow",
      "Action": [
        "sts:AssumeRole"
	    ],
      "Resource": "arn:aws:iam::*:role/${local.lambda_function_map_xosphere_organization_ri_sub_account_reporter}-lambda-assume-role"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "xosphere_organization_ri_sub_account_reporter_role_policy_service_linked_roles" {
  name = "${local.lambda_function_map_xosphere_organization_ri_sub_account_reporter}-lambda-policy-service-linked-roles"
  role = aws_iam_role.xosphere_organization_ri_sub_account_reporter_role.id
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowLambdaServiceLinkedRole",
      "Effect": "Allow",
      "Action": [
        "iam:CreateServiceLinkedRole"
	    ],
      "Resource": [
        "arn:aws:iam::*:role/aws-service-role/lambda.amazonaws.com/*"
      ],
      "Condition": {
        "StringLike": {
          "iam:AWSServiceName": [
            "lambda.amazonaws.com"
          ]
        }
      }
    },
    {
      "Sid": "AllowLambdaServiceLinkedRolePolicies",
      "Effect": "Allow",
      "Action": [
        "iam:AttachRolePolicy",
        "iam:PutRolePolicy"
	    ],
      "Resource": "arn:aws:iam::*:role/aws-service-role/lambda.amazonaws.com/*"
    }
  ]
}
EOF
}

resource "aws_cloudwatch_log_group" "xosphere_organization_ri_sub_account_reporter_log_group" {
  name = "/aws/lambda/${local.lambda_function_map_xosphere_organization_ri_sub_account_reporter}"
  retention_in_days = 30
}

resource "aws_lambda_function" "xosphere_organization_ri_sub_account_reporter_lambda_function" {
  s3_bucket = local.s3_bucket
  s3_key = "org/ri-sub-acct-reporter-lambda-${local.version}.zip"
  description = "Xosphere Organization RI sub-account reporter"
  environment {
    variables = {
      API_TOKEN_ARN = local.api_token_arn
      ENDPOINT_URL = local.endpoints_map_xosphere_api_endpoint
      ORGANIZATION_RI_REPORTER_SQS_QUEUE_URL = aws_sqs_queue.xosphere_organization_ri_sub_account_submission_queue.url
      ORGANIZATION_RI_REPORTER_KMS_KEY = aws_kms_key.xosphere_mgmt_cmk.id
      RI_SUB_ACCOUNT_DATA_BUCKET = aws_s3_bucket.organization_ri_sub_account_data_bucket.id
    }
  }
  function_name = local.lambda_function_map_xosphere_organization_ri_sub_account_reporter
  handler = "ri-sub-acct-reporter"
  memory_size = 1024
  role = aws_iam_role.xosphere_organization_ri_sub_account_reporter_role.arn
  runtime = "go1.x"
  timeout = 900
  depends_on = [ aws_cloudwatch_log_group.xosphere_organization_ri_sub_account_reporter_log_group ]
}

resource "aws_lambda_event_source_mapping" "xosphere_organization_ri_sub_account_reporter_event_source_mapping" {
  batch_size = 1
  enabled = true
  event_source_arn = aws_sqs_queue.xosphere_organization_ri_sub_account_request_queue.arn
  function_name = aws_lambda_function.xosphere_organization_ri_sub_account_reporter_lambda_function.arn
  depends_on = [ aws_iam_role.xosphere_organization_ri_sub_account_reporter_role ]
}

resource "aws_lambda_permission" "xosphere_organization_ri_sub_account_reporter_lambda_permission" {
  action = "lambda:InvokeFunction"
  function_name = aws_lambda_function.xosphere_organization_ri_sub_account_reporter_lambda_function.arn
  principal = "sqs.amazonaws.com"
  source_arn = aws_sqs_queue.xosphere_organization_ri_sub_account_request_queue.arn
}

resource "aws_s3_bucket" "organization_ri_sub_account_data_access_logs_bucket" {
  count = var.create_logging_buckets ? 1 : 0
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "aws:kms"
        kms_master_key_id = aws_kms_key.xosphere_mgmt_cmk.arn
      }
    }
  }
  force_destroy = true
  bucket = var.organization_ri_sub_account_data_access_logs_bucket_name_override != null ? var.organization_ri_sub_account_data_access_logs_bucket_name_override : null
}

resource "aws_s3_bucket_public_access_block" "organization_ri_sub_account_data_access_logs_bucket" {
  count = var.create_logging_buckets ? 1 : 0
  bucket = aws_s3_bucket.organization_ri_sub_account_data_access_logs_bucket[0].id

  block_public_acls   = true
  block_public_policy = true
  ignore_public_acls = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "organization_ri_sub_account_data_access_logs_bucket_policy" {
  count = var.create_logging_buckets ? 1 : 0
  bucket = aws_s3_bucket.organization_ri_sub_account_data_access_logs_bucket[0].id
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "S3ServerAccessLogsPolicy",
      "Resource": "${aws_s3_bucket.organization_ri_sub_account_data_access_logs_bucket[0].arn}/*",
      "Effect": "Allow",
      "Principal": {
        "Service": "logging.s3.amazonaws.com"
      },
      "Action": [
        "s3:PutObject"
      ],
      "Condition": {
        "ArnLike": {
          "aws:SourceArn": "${aws_s3_bucket.organization_ri_sub_account_data_bucket.arn}"
        },
        "StringEquals": {
          "aws:SourceAccount": "${data.aws_caller_identity.current.account_id}"
        }
      }
    },
    {
      "Action": [
        "s3:*"
      ],
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
      },
      "Resource": [
        "${aws_s3_bucket.organization_ri_sub_account_data_access_logs_bucket[0].arn}",
        "${aws_s3_bucket.organization_ri_sub_account_data_access_logs_bucket[0].arn}/*"
      ]
    }  
  ]
}
EOF
}

resource "aws_s3_bucket" "organization_ri_sub_account_data_bucket" {
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "aws:kms"
        kms_master_key_id = aws_kms_key.xosphere_mgmt_cmk.arn
      }
    }
  }

  dynamic "logging" {
    for_each = var.create_logging_buckets ? [1] : []
    content {
      target_bucket = var.create_logging_buckets ? aws_s3_bucket.organization_ri_sub_account_data_access_logs_bucket[0].id : null
      target_prefix = var.create_logging_buckets ? "xosphere-org-ri-sub-account-data-logs" : null
    }
  }
  force_destroy = true
  bucket = var.organization_ri_sub_account_data_bucket_name_override != null ? var.organization_ri_sub_account_data_bucket_name_override : null
  tags = {
    "xosphere.io/instance-orchestrator/is-org-ri-sub-account-bucket": "true"
  }
}

resource "aws_s3_bucket_public_access_block" "organization_ri_sub_account_data_bucket" {
  bucket = aws_s3_bucket.organization_ri_sub_account_data_bucket.id

  block_public_acls   = true
  block_public_policy = true
  ignore_public_acls = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "organization_ri_sub_account_data_bucket_policy" {
  bucket = aws_s3_bucket.organization_ri_sub_account_data_bucket.id
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "s3:*"
      ],
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
      },
      "Resource": [
        "${aws_s3_bucket.organization_ri_sub_account_data_bucket.arn}",
        "${aws_s3_bucket.organization_ri_sub_account_data_bucket.arn}/*"   
      ]     
    },
    {
      "Action": [
        "s3:GetObject",
        "s3:GetObjectVersion",
        "s3:GetObjectVersionTagging"
      ],
      "Effect": "Allow",
      "Resource": "${aws_s3_bucket.organization_ri_sub_account_data_bucket.arn}/*",
      "Principal": {
        "AWS": "${aws_iam_role.xosphere_organization_ri_sub_account_submission_processor_role.arn}"
      }
    }
  ]
}
EOF
}

resource "aws_sqs_queue" "xosphere_organization_ri_sub_account_request_queue" {
  name = "xosphere-instance-orchestrator-org-ri-sub-acct-requests"
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.xosphere_organization_ri_sub_account_request_dl_queue.arn
    maxReceiveCount = 5
  })

  visibility_timeout_seconds = 1020
  kms_master_key_id = aws_kms_key.xosphere_mgmt_cmk.id
  kms_data_key_reuse_period_seconds = 300
}

resource "aws_sqs_queue" "xosphere_organization_ri_sub_account_request_dl_queue" {
  name = "xosphere-instance-orchestrator-org-ri-sub-acct-requests-dlq"
  visibility_timeout_seconds = 1020
  kms_master_key_id = aws_kms_key.xosphere_mgmt_cmk.id
  kms_data_key_reuse_period_seconds = 300
}

resource "aws_iam_role" "xosphere_organization_ri_sub_account_requester_role" {
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": {
    "Action": [ "sts:AssumeRole" ],
    "Effect": "Allow",
    "Principal": {
      "Service": [ "lambda.amazonaws.com" ]
    }
  }
}
EOF
  managed_policy_arns = [ ]
  path = "/"
  name = "${local.lambda_function_map_xosphere_organization_ri_sub_account_requester}-lambda-role"
}

resource "aws_iam_role_policy" "xosphere_organization_ri_sub_account_requester_role_policy" {
  name = "${local.lambda_function_map_xosphere_organization_ri_sub_account_requester}-lambda-policy"
  role = aws_iam_role.xosphere_organization_ri_sub_account_requester_role.id
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowLogOperationsOnXosphereLogGroups",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
	    ],
      "Resource": [
        "arn:aws:logs:*:*:log-group:/aws/lambda/xosphere-*",
        "arn:aws:logs:*:*:log-group:/aws/lambda/xosphere-*:log-stream:*"
      ]
    },  
    {
      "Sid": "AllowOrgKmsOperations",
      "Effect": "Allow",
      "Action": [
        "kms:Decrypt",
        "kms:GenerateDataKey"
	    ],
      "Resource": "${aws_kms_key.xosphere_mgmt_cmk.arn}"
    },  
    {
      "Sid": "AllowOrgPublishSqs",
      "Effect": "Allow",
      "Action": [
        "sqs:SendMessage"
	    ],
      "Resource": "${aws_sqs_queue.xosphere_organization_ri_sub_account_request_queue.arn}"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "xosphere_organization_ri_sub_account_requester_role_policy_service_linked_roles" {
  name = "${local.lambda_function_map_xosphere_organization_ri_sub_account_requester}-lambda-policy-service-linked-roles"
  role = aws_iam_role.xosphere_organization_ri_sub_account_requester_role.id
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowLambdaServiceLinkedRole",
      "Effect": "Allow",
      "Action": [
        "iam:CreateServiceLinkedRole"
	    ],
      "Resource": [
        "arn:aws:iam::*:role/aws-service-role/lambda.amazonaws.com/*"
      ],
      "Condition": {
        "StringLike": {
          "iam:AWSServiceName": [
            "lambda.amazonaws.com"
          ]
        }
      }
    },
    {
      "Sid": "AllowLambdaServiceLinkedRolePolicies",
      "Effect": "Allow",
      "Action": [
        "iam:AttachRolePolicy",
        "iam:PutRolePolicy"
	    ],
      "Resource": "arn:aws:iam::*:role/aws-service-role/lambda.amazonaws.com/*"
    }
  ]
}
EOF
}

resource "aws_cloudwatch_log_group" "xosphere_organization_ri_sub_account_requester_log_group" {
  name = "/aws/lambda/${local.lambda_function_map_xosphere_organization_ri_sub_account_requester}"
  retention_in_days = 30
}

resource "aws_lambda_function" "xosphere_organization_ri_sub_account_requester_lambda_function" {
  s3_bucket = local.s3_bucket
  s3_key = "org/ri-sub-acct-requester-lambda-${local.version}.zip"
  description = "Xosphere Organization RI sub-account requester"
  environment {
    variables = {
      ORGANIZATION_RI_REQUESTER_SQS_QUEUE_URL = aws_sqs_queue.xosphere_organization_ri_sub_account_request_queue.url
      ORGANIZATION_RI_REQUESTER_KMS_KEY = aws_kms_key.xosphere_mgmt_cmk.id
      ORGANIZATION_RI_PURCHASING_ACCOUNTS = join(",", var.ri_purchasing_accounts)
    }
  }
  function_name = local.lambda_function_map_xosphere_organization_ri_sub_account_requester
  handler = "ri-sub-acct-requester"
  memory_size = 256
  role = aws_iam_role.xosphere_organization_ri_sub_account_requester_role.arn
  runtime = "go1.x"
  timeout = 900
  depends_on = [ aws_cloudwatch_log_group.xosphere_organization_ri_sub_account_requester_log_group ]
}

resource "aws_lambda_permission" "xosphere_organization_ri_sub_account_requester_lambda_permission" {
  action = "lambda:InvokeFunction"
  function_name = aws_lambda_function.xosphere_organization_ri_sub_account_requester_lambda_function.arn
  principal = "events.amazonaws.com"
  source_arn = aws_cloudwatch_event_rule.xosphere_organization_ri_sub_account_requester_schedule.arn
}

resource "aws_cloudwatch_event_rule" "xosphere_organization_ri_sub_account_requester_schedule" {
  name = "${local.lambda_function_map_xosphere_organization_ri_sub_account_requester}-schedule-event-rule"
  description = "Schedule for launching Xosphere AWS Organization RI sub account requester"
  schedule_expression = "cron(${var.organization_ri_sub_account_requester_schedule_expression})"
  is_enabled = true
}

resource "aws_cloudwatch_event_target" "xosphere_organization_ri_sub_account_requester_schedule_target" {
  arn = aws_lambda_function.xosphere_organization_ri_sub_account_requester_lambda_function.arn
  rule = aws_cloudwatch_event_rule.xosphere_organization_ri_sub_account_requester_schedule.name
  target_id = "${local.lambda_function_map_xosphere_organization_ri_sub_account_requester}-schedule"
}

resource "aws_lambda_function" "xosphere_organization_instance_state_event_collector_lambda_function" {
  s3_bucket = local.s3_bucket
  s3_key = "org/inst-state-event-collector-lambda-${local.version}.zip"
  description = "Xosphere Organization Instance State Event Collector"
  environment {
    variables = {
      ORGANIZATION_DATA_S3_BUCKET = aws_s3_bucket.organization_data_bucket.id
      ORGANIZATION_INVENTORY_DATA_PROCESSOR_SQS_QUEUE_URL = aws_sqs_queue.xosphere_organization_inventory_data_processor_queue.url
    }
  }
  function_name = local.lambda_function_map_xosphere_organization_instance_state_event_collector
  handler = "inst-state-event-collector"
  memory_size = 256
  role = aws_iam_role.xosphere_organization_instance_state_event_collector_lambda_role.arn
  runtime = "go1.x"
  timeout = 300
  reserved_concurrent_executions = 1
  depends_on = [ aws_cloudwatch_log_group.xosphere_organization_instance_state_event_collector_log_group ]
}

resource "aws_iam_role" "xosphere_organization_instance_state_event_collector_lambda_role" {
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": {
    "Action": [ "sts:AssumeRole" ],
    "Effect": "Allow",
    "Principal": {
      "Service": [ "lambda.amazonaws.com" ]
    }
  }
}
EOF
  managed_policy_arns = [ ]
  path = "/"
  name = "${local.lambda_function_map_xosphere_organization_instance_state_event_collector}-lambda-role"
}

resource "aws_iam_role_policy" "xosphere_organization_instance_state_event_collector_lambda_role_policy" {
  name = "${local.lambda_function_map_xosphere_organization_instance_state_event_collector}-lambda-policy"
  role = aws_iam_role.xosphere_organization_instance_state_event_collector_lambda_role.id
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowLogOperationsOnXosphereLogGroups",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
	    ],
      "Resource": [
        "arn:aws:logs:*:*:log-group:/aws/lambda/xosphere-*",
        "arn:aws:logs:*:*:log-group:/aws/lambda/xosphere-*:log-stream:*"
      ]
    },  
    {
      "Sid": "AllowS3OperationsOnXosphereObjects",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:GetObjectVersion",
        "s3:GetObjectVersionTagging",
        "s3:PutObject",
        "s3:PutObjectTagging",
        "s3:PutObjectVersionTagging"
	    ],
      "Resource": "arn:aws:s3:::xosphere-*/*"
    },
    {
      "Sid": "AllowS3OperationsOnXosphereBuckets",
      "Effect": "Allow",
      "Action": [
        "s3:ListBucket",
        "s3:ListBucketVersions"
	    ],
      "Resource": "arn:aws:s3:::xosphere-*"
    },
    {
      "Sid": "AllowInvUpdateReadSqs",
      "Effect": "Allow",
      "Action": [
        "sqs:ChangeMessageVisibility",
        "sqs:DeleteMessage",
        "sqs:GetQueueAttributes",
        "sqs:ReceiveMessage",
        "sqs:GetQueueUrl"
	    ],
      "Resource": "${aws_sqs_queue.xosphere_organization_instance_state_event_collector_queue.arn}"
    },
    {
      "Sid": "AllowSecretManagerOperations",
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue"
	    ],
      "Resource": "${local.api_token_arn}"
    },
    {
      "Sid": "AllowKmsOperations",
      "Effect": "Allow",
      "Action": [
        "kms:Decrypt"
	    ],
      "Resource": "${local.kms_key_pattern}"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "xosphere_organization_instance_state_event_collector_lambda_role_policy_service_linked_roles" {
  name = "${local.lambda_function_map_xosphere_organization_instance_state_event_collector}-lambda-policy-service-linked-roles"
  role = aws_iam_role.xosphere_organization_instance_state_event_collector_lambda_role.id
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowLambdaServiceLinkedRole",
      "Effect": "Allow",
      "Action": [
        "iam:CreateServiceLinkedRole"
	    ],
      "Resource": [
        "arn:aws:iam::*:role/aws-service-role/lambda.amazonaws.com/*"
      ],
      "Condition": {
        "StringLike": {
          "iam:AWSServiceName": [
            "lambda.amazonaws.com"
          ]
        }
      }
    },
    {
      "Sid": "AllowLambdaServiceLinkedRolePolicies",
      "Effect": "Allow",
      "Action": [
        "iam:AttachRolePolicy",
        "iam:PutRolePolicy"
	    ],
      "Resource": "arn:aws:iam::*:role/aws-service-role/lambda.amazonaws.com/*"
    }
  ]
}
EOF
}

resource "aws_cloudwatch_log_group" "xosphere_organization_instance_state_event_collector_log_group" {
  name = "/aws/lambda/${local.lambda_function_map_xosphere_organization_instance_state_event_collector}"
  retention_in_days = 30
}

resource "aws_lambda_permission" "xosphere_organization_instance_state_event_collector_lambda_permission" {
  action = "lambda:InvokeFunction"
  function_name = aws_lambda_function.xosphere_organization_instance_state_event_collector_lambda_function.arn
  principal = "sqs.amazonaws.com"
  source_arn = aws_sqs_queue.xosphere_organization_instance_state_event_collector_queue.arn
}

resource "aws_lambda_event_source_mapping" "xosphere_organization_instance_state_event_collector_event_source_mapping" {
  batch_size = 150
  maximum_batching_window_in_seconds = 10
  enabled = true
  event_source_arn = aws_sqs_queue.xosphere_organization_instance_state_event_collector_queue.arn
  function_name = aws_lambda_function.xosphere_organization_instance_state_event_collector_lambda_function.arn
  depends_on = [ aws_iam_role.xosphere_organization_instance_state_event_collector_lambda_role ]
}

resource "aws_sqs_queue" "xosphere_organization_instance_state_event_collector_queue" {
  name = local.well_known_names_xosphere_organization_instance_state_event_collector_queue_name
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.xosphere_organization_inventory_data_processor_dl_queue.arn
    maxReceiveCount = 5
  })

  visibility_timeout_seconds = 1020
  kms_master_key_id = aws_kms_key.xosphere_mgmt_cmk.id
}

resource "aws_sqs_queue_policy" "xosphere_organization_instance_state_event_collector_queue_policy" {
  queue_url = aws_sqs_queue.xosphere_organization_instance_state_event_collector_queue.id

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowSendSqsUpdates",
      "Effect": "Allow",
      "Principal": {
        "AWS": "*"
      },
      "Action": "sqs:SendMessage",
      "Resource": "${aws_sqs_queue.xosphere_organization_instance_state_event_collector_queue.arn}",
      "Condition": {
        "StringEquals": {
          "aws:PrincipalOrgID": "${var.aws_organization_id}" %{ if false } # should use a pseudo parameter, but AWS doesn't yet provide one.  https://github.com/aws-cloudformation/cloudformation-coverage-roadmap/issues/160 %{ endif }
        }
%{ if var.enable_enhanced_security }        
        ,
        "ArnLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/${local.well_known_names_xosphere_event_router_lambda_role}"
        }
%{ endif }
      }
    }
%{ if local.enable_org_inv_mgmt_xosphere }
    ,{
      "Sid": "AllowSendSqsUpdatesEnricher",
      "Effect": "Allow",
      "Principal": {
        "AWS": "${aws_iam_role.xosphere_organization_inventory_data_enricher_lambda_role[0].arn}"
      },
      "Action": "sqs:SendMessage",
      "Resource": "${aws_sqs_queue.xosphere_organization_instance_state_event_collector_queue.arn}"
    }
%{ endif }
  ]
}
EOF
}

resource "aws_sqs_queue" "xosphere_organization_instance_state_event_collector_dl_queue" {
  name = "xosphere-instance-orchestrator-org-inst-state-event-collector-launch-dlq"
  visibility_timeout_seconds = 1020
  kms_master_key_id = aws_kms_key.xosphere_mgmt_cmk.id
}

resource "aws_lambda_function" "xosphere_organization_inventory_baseline_merger_lambda_function" {
  count = local.enable_org_inv_mgmt_xosphere ? 1 : 0
  s3_bucket = local.s3_bucket
  s3_key = "org/inv-baseline-merger-lambda-${local.version}.zip"
  description = "Xosphere Organization Inventory Baseline Merger"
  environment {
    variables = {
      API_TOKEN_ARN = local.api_token_arn
      ENDPOINT_URL = local.endpoints_map_xosphere_api_endpoint
      ORGANIZATION_DATA_S3_BUCKET = aws_s3_bucket.organization_data_bucket.id
      ORGANIZATION_INVENTORY_DATA_PROCESSOR_SQS_QUEUE_URL = aws_sqs_queue.xosphere_organization_inventory_data_processor_queue.url
    }
  }
  function_name = local.lambda_function_map_xosphere_organization_inventory_baseline_merger
  handler = "inv-baseline-merger"
  memory_size = 1024
  role = aws_iam_role.xosphere_organization_inventory_baseline_merger_lambda_role[0].arn
  runtime = "go1.x"
  timeout = 900
  reserved_concurrent_executions = 1
  depends_on = [ aws_cloudwatch_log_group.xosphere_organization_inventory_baseline_merger_log_group ]
}

resource "aws_iam_role" "xosphere_organization_inventory_baseline_merger_lambda_role" {
  count = local.enable_org_inv_mgmt_xosphere ? 1 : 0
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": {
    "Action": [ "sts:AssumeRole" ],
    "Effect": "Allow",
    "Principal": {
      "Service": [ "lambda.amazonaws.com" ]
    }
  }
}
EOF
  managed_policy_arns = [ ]
  path = "/"
  name = "${local.lambda_function_map_xosphere_organization_inventory_baseline_merger}-lambda-role"
}

resource "aws_iam_role_policy" "xosphere_organization_inventory_baseline_merger_lambda_role_policy" {
  count = local.enable_org_inv_mgmt_xosphere ? 1 : 0
  name = "${local.lambda_function_map_xosphere_organization_inventory_baseline_merger}-lambda-policy"
  role = aws_iam_role.xosphere_organization_inventory_baseline_merger_lambda_role[0].id
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowLogOperationsOnXosphereLogGroups",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
	    ],
      "Resource": [
        "arn:aws:logs:*:*:log-group:/aws/lambda/xosphere-*",
        "arn:aws:logs:*:*:log-group:/aws/lambda/xosphere-*:log-stream:*"
      ]
    },
    {
      "Sid": "AllowS3OperationsOnXosphereObjects",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:GetObjectVersion",
        "s3:GetObjectVersionTagging",
        "s3:PutObject",
        "s3:PutObjectTagging",
        "s3:PutObjectVersionTagging"
	    ],
      "Resource": "arn:aws:s3:::xosphere-*/*"
    },
    {
      "Sid": "AllowS3OperationsOnXosphereBuckets",
      "Effect": "Allow",
      "Action": [
        "s3:ListBucket",
        "s3:ListBucketVersions"
	    ],
      "Resource": "arn:aws:s3:::xosphere-*"
    },
    {
      "Sid": "AllowSecretManagerOperations",
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue"
	    ],
      "Resource": "${local.api_token_arn}"
    },
    {
      "Sid": "AllowKmsOperations",
      "Effect": "Allow",
      "Action": [
        "kms:Decrypt"
	    ],
      "Resource": "${local.kms_key_pattern}"
    },
    {
      "Sid": "AllowOrgKmsOperations",
      "Effect": "Allow",
      "Action": [
        "kms:Decrypt",
        "kms:GenerateDataKey"
	    ],
      "Resource": "${aws_kms_key.xosphere_mgmt_cmk.arn}"
    },
    {
      "Sid": "AllowOrgReadSqs",
      "Effect": "Allow",
      "Action": [
        "sqs:ChangeMessageVisibility",
        "sqs:DeleteMessage",
        "sqs:GetQueueAttributes",
        "sqs:ReceiveMessage",
        "sqs:GetQueueUrl"
	    ],
      "Resource": "${aws_sqs_queue.xosphere_organization_inventory_report_submission_queue[0].arn}"      
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "xosphere_organization_inventory_baseline_merger_lambda_role_policy_service_linked_roles" {
  count = local.enable_org_inv_mgmt_xosphere ? 1 : 0
  name = "${local.lambda_function_map_xosphere_organization_inventory_baseline_merger}-lambda-policy-service-linked-roles"
  role = aws_iam_role.xosphere_organization_inventory_baseline_merger_lambda_role[0].id
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowLambdaServiceLinkedRole",
      "Effect": "Allow",
      "Action": [
        "iam:CreateServiceLinkedRole"
	    ],
      "Resource": [
        "arn:aws:iam::*:role/aws-service-role/lambda.amazonaws.com/*"
      ],
      "Condition": {
        "StringLike": {
          "iam:AWSServiceName": [
            "lambda.amazonaws.com"
          ]
        }
      }
    },
    {
      "Sid": "AllowLambdaServiceLinkedRolePolicies",
      "Effect": "Allow",
      "Action": [
        "iam:AttachRolePolicy",
        "iam:PutRolePolicy"
	    ],
      "Resource": "arn:aws:iam::*:role/aws-service-role/lambda.amazonaws.com/*"
    }
  ]
}
EOF
}

resource "aws_cloudwatch_log_group" "xosphere_organization_inventory_baseline_merger_log_group" {
  count = local.enable_org_inv_mgmt_xosphere ? 1 : 0
  name = "/aws/lambda/${local.lambda_function_map_xosphere_organization_inventory_baseline_merger}"
  retention_in_days = 30
}

resource "aws_lambda_permission" "xosphere_organization_inventory_baseline_merger_lambda_permission" {
  count = local.enable_org_inv_mgmt_xosphere ? 1 : 0
  action = "lambda:InvokeFunction"
  function_name = aws_lambda_function.xosphere_organization_inventory_baseline_merger_lambda_function[0].arn
  principal = "sqs.amazonaws.com"
  source_arn = aws_sqs_queue.xosphere_organization_inventory_report_submission_queue[0].arn
}

resource "aws_lambda_event_source_mapping" "xosphere_organization_inventory_baseline_merger_event_source_mapping" {
  count = local.enable_org_inv_mgmt_xosphere ? 1 : 0
  batch_size = 50
  maximum_batching_window_in_seconds = 30
  enabled = true
  event_source_arn = aws_sqs_queue.xosphere_organization_inventory_report_submission_queue[0].arn
  function_name = aws_lambda_function.xosphere_organization_inventory_baseline_merger_lambda_function[0].arn
  depends_on = [ aws_iam_role.xosphere_organization_inventory_baseline_merger_lambda_role[0] ]
}

resource "aws_lambda_function" "xosphere_organization_inventory_baseline_reporter_lambda_function" {
  count = local.enable_org_inv_mgmt_xosphere ? 1 : 0
  s3_bucket = local.s3_bucket
  s3_key = "org/inv-baseline-reporter-lambda-${local.version}.zip"
  description = "Xosphere Organization Inventory Baseline Reporter"
  environment {
    variables = {
      API_TOKEN_ARN = local.api_token_arn
      ENDPOINT_URL = local.endpoints_map_xosphere_api_endpoint
      ORGANIZATION_INV_REPORTER_SQS_QUEUE_URL = aws_sqs_queue.xosphere_organization_inventory_report_submission_queue[0].url
      ORGANIZATION_DATA_S3_BUCKET = aws_s3_bucket.organization_data_bucket.id
    }
  }
  function_name = local.lambda_function_map_xosphere_organization_inventory_baseline_reporter
  handler = "inv-baseline-reporter"
  memory_size = 1024
  role = aws_iam_role.xosphere_organization_inventory_baseline_reporter_lambda_role[0].arn
  runtime = "go1.x"
  timeout = 900
  depends_on = [ aws_cloudwatch_log_group.xosphere_organization_inventory_baseline_reporter_log_group ]
}

resource "aws_iam_role" "xosphere_organization_inventory_baseline_reporter_lambda_role" {
  count = local.enable_org_inv_mgmt_xosphere ? 1 : 0
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": {
    "Action": [ "sts:AssumeRole" ],
    "Effect": "Allow",
    "Principal": {
      "Service": [ "lambda.amazonaws.com" ]
    }
  }
}
EOF
  managed_policy_arns = [ ]
  path = "/"
  name = "${local.lambda_function_map_xosphere_organization_inventory_baseline_reporter}-lambda-role"
}

resource "aws_iam_role_policy" "xosphere_organization_inventory_baseline_reporter_lambda_role_policy" {
  count = local.enable_org_inv_mgmt_xosphere ? 1 : 0
  name = "${local.lambda_function_map_xosphere_organization_inventory_baseline_reporter}-lambda-policy"
  role = aws_iam_role.xosphere_organization_inventory_baseline_reporter_lambda_role[0].id
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowLogOperationsOnXosphereLogGroups",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
	    ],
      "Resource": [
        "arn:aws:logs:*:*:log-group:/aws/lambda/xosphere-*",
        "arn:aws:logs:*:*:log-group:/aws/lambda/xosphere-*:log-stream:*"
      ]
    },  
    {
      "Sid": "AllowS3OperationsOnXosphereObjects",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:GetObjectVersion",
        "s3:GetObjectVersionTagging",
        "s3:PutObject",
        "s3:PutObjectTagging",
        "s3:PutObjectVersionTagging"
	    ],
      "Resource": "arn:aws:s3:::xosphere-*/*"
    },
    {
      "Sid": "AllowS3OperationsOnXosphereBuckets",
      "Effect": "Allow",
      "Action": [
        "s3:ListBucket",
        "s3:ListBucketVersions"
	    ],
      "Resource": "arn:aws:s3:::xosphere-*"
    },
    {
      "Sid": "AllowSecretManagerOperations",
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue"
	    ],
      "Resource": "${local.api_token_arn}"
    },
    {
      "Sid": "AllowKmsOperations",
      "Effect": "Allow",
      "Action": [
        "kms:Decrypt"
	    ],
      "Resource": "${local.kms_key_pattern}"
    },
    {
      "Sid": "AllowOrgKmsOperations",
      "Effect": "Allow",
      "Action": [
        "kms:Decrypt",
        "kms:GenerateDataKey"
	    ],
      "Resource": "${aws_kms_key.xosphere_mgmt_cmk.arn}"
    },
    {
      "Sid": "AllowOrgPublishSqs",
      "Effect": "Allow",
      "Action": [
        "sqs:SendMessage"
	    ],
      "Resource": "${aws_sqs_queue.xosphere_organization_inventory_report_submission_queue[0].arn}"
    },
    {
      "Sid": "AllowOrgReadSqs",
      "Effect": "Allow",
      "Action": [
        "sqs:ChangeMessageVisibility",
        "sqs:DeleteMessage",
        "sqs:GetQueueAttributes",
        "sqs:ReceiveMessage",
        "sqs:GetQueueUrl"
	    ],
      "Resource": "${aws_sqs_queue.xosphere_organization_inventory_report_request_queue[0].arn}"
    },
    {
      "Sid": "AssumeCollectorRole",
      "Effect": "Allow",
      "Action": [
        "sts:AssumeRole"
	    ],
      "Resource": "${join("", ["arn:aws:iam::*:role/", local.well_known_names_xosphere_organization_inventory_collector_role])}"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "xosphere_organization_inventory_baseline_reporter_lambda_role_policy_service_linked_roles" {
  count = local.enable_org_inv_mgmt_xosphere ? 1 : 0
  name = "${local.lambda_function_map_xosphere_organization_inventory_baseline_reporter}-lambda-policy-service-linked-roles"
  role = aws_iam_role.xosphere_organization_inventory_baseline_reporter_lambda_role[0].id
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowLambdaServiceLinkedRole",
      "Effect": "Allow",
      "Action": [
        "iam:CreateServiceLinkedRole"
	    ],
      "Resource": [
        "arn:aws:iam::*:role/aws-service-role/lambda.amazonaws.com/*"
      ],
      "Condition": {
        "StringLike": {
          "iam:AWSServiceName": [
            "lambda.amazonaws.com"
          ]
        }
      }
    },
    {
      "Sid": "AllowLambdaServiceLinkedRolePolicies",
      "Effect": "Allow",
      "Action": [
        "iam:AttachRolePolicy",
        "iam:PutRolePolicy"
	    ],
      "Resource": "arn:aws:iam::*:role/aws-service-role/lambda.amazonaws.com/*"
    }
  ]
}
EOF
}

resource "aws_cloudwatch_log_group" "xosphere_organization_inventory_baseline_reporter_log_group" {
  count = local.enable_org_inv_mgmt_xosphere ? 1 : 0
  name = "/aws/lambda/${local.lambda_function_map_xosphere_organization_inventory_baseline_reporter}"
  retention_in_days = 30
}

resource "aws_lambda_permission" "xosphere_organization_inventory_baseline_reporter_lambda_permission" {
  count = local.enable_org_inv_mgmt_xosphere ? 1 : 0
  action = "lambda:InvokeFunction"
  function_name = aws_lambda_function.xosphere_organization_inventory_baseline_reporter_lambda_function[0].arn
  principal = "sqs.amazonaws.com"
  source_arn = aws_sqs_queue.xosphere_organization_inventory_report_request_queue[0].arn
}

resource "aws_lambda_event_source_mapping" "xosphere_organization_inventory_baseline_reporter_event_source_mapping" {
  count = local.enable_org_inv_mgmt_xosphere ? 1 : 0
  batch_size = 1
  enabled = true
  event_source_arn = aws_sqs_queue.xosphere_organization_inventory_report_request_queue[0].arn
  function_name = aws_lambda_function.xosphere_organization_inventory_baseline_reporter_lambda_function[0].arn
  depends_on = [ aws_iam_role.xosphere_organization_inventory_baseline_reporter_lambda_role[0] ]
}

resource "aws_lambda_function" "xosphere_organization_inventory_baseline_requester_lambda_function" {
  count = local.enable_org_inv_mgmt_xosphere ? 1 : 0
  s3_bucket = local.s3_bucket
  s3_key = "org/inv-baseline-requester-lambda-${local.version}.zip"
  description = "Xosphere AWS Organization Inventory Baseline Requester"
  environment {
    variables = {
      ORGANIZATION_INV_REPORT_REQUEST_SQS_QUEUE_URL = aws_sqs_queue.xosphere_organization_inventory_report_request_queue[0].url
      AWS_ORGANIZATION_MGMT_ACCOUNT_ID= var.aws_organization_mgmt_account_id
    }
  }
  function_name = local.lambda_function_map_xosphere_organization_inventory_baseline_requester
  handler = "inv-baseline-requester"
  memory_size = 1024
  role = aws_iam_role.xosphere_organization_inventory_baseline_requester_lambda_role[0].arn
  runtime = "go1.x"
  timeout = 900
  depends_on = [ aws_cloudwatch_log_group.xosphere_organization_inventory_baseline_requester_log_group ]
}

resource "aws_iam_role" "xosphere_organization_inventory_baseline_requester_lambda_role" {
  count = local.enable_org_inv_mgmt_xosphere ? 1 : 0
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": {
    "Action": [ "sts:AssumeRole" ],
    "Effect": "Allow",
    "Principal": {
      "Service": [ "lambda.amazonaws.com" ]
    }
  }
}
EOF
  managed_policy_arns = [ ]
  path = "/"
  name = "${local.lambda_function_map_xosphere_organization_inventory_baseline_requester}-lambda-role"
}

resource "aws_iam_role_policy" "xosphere_organization_inventory_baseline_requester_lambda_role_policy" {
  count = local.enable_org_inv_mgmt_xosphere ? 1 : 0
  name = "${local.lambda_function_map_xosphere_organization_inventory_baseline_requester}-lambda-policy"
  role = aws_iam_role.xosphere_organization_inventory_baseline_requester_lambda_role[0].id
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowLogOperationsOnXosphereLogGroups",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
	    ],
      "Resource": [
        "arn:aws:logs:*:*:log-group:/aws/lambda/xosphere-*",
        "arn:aws:logs:*:*:log-group:/aws/lambda/xosphere-*:log-stream:*"
      ]
    },  
    {
      "Sid": "AllowS3OperationsOnXosphereObjects",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:GetObjectVersion",
        "s3:GetObjectVersionTagging",
        "s3:PutObject",
        "s3:PutObjectTagging",
        "s3:PutObjectVersionTagging"
	    ],
      "Resource": "arn:aws:s3:::xosphere-*/*"
    },
    {
      "Sid": "AllowS3OperationsOnXosphereBuckets",
      "Effect": "Allow",
      "Action": [
        "s3:ListBucket",
        "s3:ListBucketVersions"
	    ],
      "Resource": "arn:aws:s3:::xosphere-*"
    },
    {
      "Sid": "AllowSecretManagerOperations",
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue"
	    ],
      "Resource": "${local.api_token_arn}"
    },
    {
      "Sid": "AllowKmsOperations",
      "Effect": "Allow",
      "Action": [
        "kms:Decrypt"
	    ],
      "Resource": "${local.kms_key_pattern}"
    },
    {
      "Sid": "AssumeOrgRole",
      "Effect": "Allow",
      "Action": [
        "sts:AssumeRole"
	    ],
      "Resource": "arn:aws:iam::${var.aws_organization_mgmt_account_id}:role/${local.lambda_function_map_xosphere_organization_ri_data_gatherer}-lambda-assume-role"
    },
    {
      "Sid": "AllowOrgKmsOperations",
      "Effect": "Allow",
      "Action": [
        "kms:Decrypt",
        "kms:GenerateDataKey"
	    ],
      "Resource": "${aws_kms_key.xosphere_mgmt_cmk.arn}"
    },
    {
      "Sid": "AllowPublishMergerSqs",
      "Effect": "Allow",
      "Action": [
        "sqs:SendMessage"
	    ],
      "Resource": "${aws_sqs_queue.xosphere_organization_inventory_report_request_queue[0].arn}"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "xosphere_organization_inventory_baseline_requester_lambda_role_policy_service_linked_roles" {
  count = local.enable_org_inv_mgmt_xosphere ? 1 : 0
  name = "${local.lambda_function_map_xosphere_organization_inventory_baseline_requester}-lambda-policy-service-linked-roles"
  role = aws_iam_role.xosphere_organization_inventory_baseline_requester_lambda_role[0].id
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowLambdaServiceLinkedRole",
      "Effect": "Allow",
      "Action": [
        "iam:CreateServiceLinkedRole"
	    ],
      "Resource": [
        "arn:aws:iam::*:role/aws-service-role/lambda.amazonaws.com/*"
      ],
      "Condition": {
        "StringLike": {
          "iam:AWSServiceName": [
            "lambda.amazonaws.com"
          ]
        }
      }
    },
    {
      "Sid": "AllowLambdaServiceLinkedRolePolicies",
      "Effect": "Allow",
      "Action": [
        "iam:AttachRolePolicy",
        "iam:PutRolePolicy"
	    ],
      "Resource": "arn:aws:iam::*:role/aws-service-role/lambda.amazonaws.com/*"
    }
  ]
}
EOF
}

resource "aws_cloudwatch_log_group" "xosphere_organization_inventory_baseline_requester_log_group" {
  count = local.enable_org_inv_mgmt_xosphere ? 1 : 0
  name = "/aws/lambda/${local.lambda_function_map_xosphere_organization_inventory_baseline_requester}"
  retention_in_days = 30
}

resource "aws_lambda_permission" "xosphere_organization_inventory_baseline_requester_lambda_permission" {
  count = local.enable_org_inv_mgmt_xosphere ? 1 : 0
  action = "lambda:InvokeFunction"
  function_name = aws_lambda_function.xosphere_organization_inventory_baseline_requester_lambda_function[0].arn
  principal = "events.amazonaws.com"
  source_arn = aws_cloudwatch_event_rule.xosphere_organization_inventory_baseline_requester_schedule[0].arn
}

resource "aws_cloudwatch_event_rule" "xosphere_organization_inventory_baseline_requester_schedule" {
  count = local.enable_org_inv_mgmt_xosphere ? 1 : 0
  name = "${local.lambda_function_map_xosphere_organization_inventory_baseline_requester}-schedule-event-rule"
  description = "Schedule for launching Xosphere AWS Organization Inventory Baseline Requester"
  schedule_expression = "cron(${var.organization_inventory_baseline_requester_schedule_expression})"
  is_enabled = true
}

resource "aws_cloudwatch_event_target" "xosphere_organization_inventory_baseline_requester_schedule_target" {
  count = local.enable_org_inv_mgmt_xosphere ? 1 : 0
  arn = aws_lambda_function.xosphere_organization_inventory_baseline_requester_lambda_function[0].arn
  rule = aws_cloudwatch_event_rule.xosphere_organization_inventory_baseline_requester_schedule[0].name
  target_id = "${local.lambda_function_map_xosphere_organization_inventory_baseline_requester}-schedule"
}

resource "aws_lambda_function" "xosphere_organization_inventory_data_enricher_lambda_function" {
  count = local.enable_org_inv_mgmt_xosphere ? 1 : 0
  s3_bucket = local.s3_bucket
  s3_key = "org/inv-data-enricher-lambda-${local.version}.zip"
  description = "Xosphere Organization Inventory Data Enricher"
  environment {
    variables = {
      API_TOKEN_ARN = local.api_token_arn
      ENDPOINT_URL = local.endpoints_map_xosphere_api_endpoint
      ORGANIZATION_EC2_STATE_CHANGE_EVENT_COLLECTOR_SQS_QUEUE_URL = aws_sqs_queue.xosphere_organization_instance_state_event_collector_queue.url
    }
  }
  function_name = local.lambda_function_map_xosphere_organization_inventory_data_enricher
  handler = "inv-data-enricher"
  memory_size = 1024
  role = aws_iam_role.xosphere_organization_inventory_data_enricher_lambda_role[0].arn
  runtime = "go1.x"
  timeout = 900
  depends_on = [ aws_cloudwatch_log_group.xosphere_organization_inventory_data_enricher_log_group ]
}

resource "aws_iam_role" "xosphere_organization_inventory_data_enricher_lambda_role" {
  count = local.enable_org_inv_mgmt_xosphere ? 1 : 0
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": {
    "Action": [ "sts:AssumeRole" ],
    "Effect": "Allow",
    "Principal": {
      "Service": [ "lambda.amazonaws.com" ]
    }
  }
}
EOF
  managed_policy_arns = [ ]
  path = "/"
  name = "${local.lambda_function_map_xosphere_organization_inventory_data_enricher}-lambda-role"
}

resource "aws_iam_role_policy" "xosphere_organization_inventory_data_enricher_lambda_role_policy" {
  count = local.enable_org_inv_mgmt_xosphere ? 1 : 0
  name = "${local.lambda_function_map_xosphere_organization_inventory_data_enricher}-lambda-policy"
  role = aws_iam_role.xosphere_organization_inventory_data_enricher_lambda_role[0].id
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowLogOperationsOnXosphereLogGroups",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
	    ],
      "Resource": [
        "arn:aws:logs:*:*:log-group:/aws/lambda/xosphere-*",
        "arn:aws:logs:*:*:log-group:/aws/lambda/xosphere-*:log-stream:*"
      ]
    },
    {
      "Sid": "AllowSecretManagerOperations",
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue"
	    ],
      "Resource": "${local.api_token_arn}"
    },
    {
      "Sid": "AllowKmsOperations",
      "Effect": "Allow",
      "Action": [
        "kms:Decrypt"
	    ],
      "Resource": "${local.kms_key_pattern}"
    },
    {
      "Sid": "AllowOrgKmsOperations",
      "Effect": "Allow",
      "Action": [
        "kms:Decrypt",
        "kms:GenerateDataKey"
	    ],
      "Resource": "${aws_kms_key.xosphere_mgmt_cmk.arn}"
    },
    {
      "Sid": "AllowOrgReadSqs",
      "Effect": "Allow",
      "Action": [
        "sqs:ChangeMessageVisibility",
        "sqs:DeleteMessage",
        "sqs:GetQueueAttributes",
        "sqs:ReceiveMessage",
        "sqs:GetQueueUrl"
	    ],
      "Resource": "${aws_sqs_queue.xosphere_organization_inventory_realtime_updates_queue[0].arn}"
    },
    {
      "Sid": "AllowOrgPublishSqs",
      "Effect": "Allow",
      "Action": [
        "sqs:SendMessage"
	    ],
      "Resource": "${aws_sqs_queue.xosphere_organization_instance_state_event_collector_queue.arn}"
    },
    {
      "Sid": "AssumeCollectorRole",
      "Effect": "Allow",
      "Action": [
        "sts:AssumeRole"
	    ],
      "Resource": "${join("", ["arn:aws:iam::*:role/", local.well_known_names_xosphere_organization_inventory_collector_role])}"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "xosphere_organization_inventory_data_enricher_lambda_role_policy_service_linked_roles" {
  count = local.enable_org_inv_mgmt_xosphere ? 1 : 0
  name = "${local.lambda_function_map_xosphere_organization_inventory_data_enricher}-lambda-policy-service-linked-roles"
  role = aws_iam_role.xosphere_organization_inventory_data_enricher_lambda_role[0].id
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowLambdaServiceLinkedRole",
      "Effect": "Allow",
      "Action": [
        "iam:CreateServiceLinkedRole"
	    ],
      "Resource": [
        "arn:aws:iam::*:role/aws-service-role/lambda.amazonaws.com/*"
      ],
      "Condition": {
        "StringLike": {
          "iam:AWSServiceName": [
            "lambda.amazonaws.com"
          ]
        }
      }
    },
    {
      "Sid": "AllowLambdaServiceLinkedRolePolicies",
      "Effect": "Allow",
      "Action": [
        "iam:AttachRolePolicy",
        "iam:PutRolePolicy"
	    ],
      "Resource": "arn:aws:iam::*:role/aws-service-role/lambda.amazonaws.com/*"
    }
  ]
}
EOF
}

resource "aws_cloudwatch_log_group" "xosphere_organization_inventory_data_enricher_log_group" {
  count = local.enable_org_inv_mgmt_xosphere ? 1 : 0
  name = "/aws/lambda/${local.lambda_function_map_xosphere_organization_inventory_data_enricher}"
  retention_in_days = 30
}

resource "aws_lambda_permission" "xosphere_organization_inventory_data_enricher_lambda_permission" {
  count = local.enable_org_inv_mgmt_xosphere ? 1 : 0
  action = "lambda:InvokeFunction"
  function_name = aws_lambda_function.xosphere_organization_inventory_data_enricher_lambda_function[0].arn
  principal = "sqs.amazonaws.com"
  source_arn = aws_sqs_queue.xosphere_organization_inventory_realtime_updates_queue[0].arn
}

resource "aws_lambda_event_source_mapping" "xosphere_organization_inventory_data_enricher_event_source_mapping" {
  count = local.enable_org_inv_mgmt_xosphere ? 1 : 0
  batch_size = 1
  enabled = true
  event_source_arn = aws_sqs_queue.xosphere_organization_inventory_realtime_updates_queue[0].arn
  function_name = aws_lambda_function.xosphere_organization_inventory_data_enricher_lambda_function[0].arn
  depends_on = [ aws_iam_role.xosphere_organization_inventory_data_enricher_lambda_role[0] ]
}

resource "aws_lambda_function" "xosphere_organization_inventory_customer_parser_lambda_function" {
  count = local.enable_org_inv_mgmt_customer ? 1 : 0
  s3_bucket = local.s3_bucket
  s3_key = "org/inv-customer-parser-lambda-${local.version}.zip"
  description = "Xosphere AWS Organization Inventory Data Processor"
  environment {
    variables = {
      ORGANIZATION_DATA_S3_BUCKET = aws_s3_bucket.organization_data_bucket.id
      CUSTOMER_INVENTORY_S3_BUCKET = aws_s3_bucket.customer_inventory_bucket[0].id
      CUSTOMER_INVENTORY_S3_FILE_PATH = var.xosphere_customer_inventory_s3_file_path
      CUSTOMER_INVENTORY_GZIP_COMPRESSED = var.xosphere_customer_inventory_gzip_compressed
      ORGANIZATION_INVENTORY_DATA_PROCESSOR_SQS_QUEUE_URL = aws_sqs_queue.xosphere_organization_inventory_data_processor_queue.url
    }
  }
  function_name = local.lambda_function_map_xosphere_organization_inventory_customer_parser
  handler = "inv-customer-parser"
  memory_size = 256
  role = aws_iam_role.xosphere_organization_inventory_customer_parser_lambda_role[0].arn
  runtime = "go1.x"
  timeout = 300
  reserved_concurrent_executions = 1
  depends_on = [ aws_cloudwatch_log_group.xosphere_organization_inventory_customer_parser_log_group ]
}

resource "aws_iam_role" "xosphere_organization_inventory_customer_parser_lambda_role" {
  count = local.enable_org_inv_mgmt_customer ? 1 : 0
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": {
    "Action": [ "sts:AssumeRole" ],
    "Effect": "Allow",
    "Principal": {
      "Service": [ "lambda.amazonaws.com" ]
    }
  }
}
EOF
  managed_policy_arns = [ ]
  path = "/"
  name = "${local.lambda_function_map_xosphere_organization_inventory_customer_parser}-lambda-role"
}

resource "aws_iam_role_policy" "xosphere_organization_inventory_customer_parser_lambda_role_policy" {
  count = local.enable_org_inv_mgmt_customer ? 1 : 0
  name = "${local.lambda_function_map_xosphere_organization_inventory_customer_parser}-lambda-policy"
  role = aws_iam_role.xosphere_organization_inventory_customer_parser_lambda_role[0].id
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowLogOperationsOnXosphereLogGroups",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
	    ],
      "Resource": [
        "arn:aws:logs:*:*:log-group:/aws/lambda/xosphere-*",
        "arn:aws:logs:*:*:log-group:/aws/lambda/xosphere-*:log-stream:*"
      ]
    },
    {
      "Sid": "AllowS3OperationsOnXosphereObjects",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:GetObjectVersion",
        "s3:GetObjectVersionTagging",
        "s3:PutObject",
        "s3:PutObjectTagging",
        "s3:PutObjectVersionTagging",
        "s3:DeleteObject"
	    ],
      "Resource": "arn:aws:s3:::xosphere-*/*"
    },
    {
      "Sid": "AllowS3OperationsOnXosphereBuckets",
      "Effect": "Allow",
      "Action": [
        "s3:ListBucket",
        "s3:ListBucketVersions"
	    ],
      "Resource": "arn:aws:s3:::xosphere-*"
    },
    {
      "Sid": "AllowInvUpdateReadSqs",
      "Effect": "Allow",
      "Action": [
        "sqs:ChangeMessageVisibility",
        "sqs:DeleteMessage",
        "sqs:GetQueueAttributes",
        "sqs:ReceiveMessage",
        "sqs:GetQueueUrl"
	    ],
      "Resource": "${aws_sqs_queue.xosphere_organization_inventory_customer_parser_queue[0].arn}"
    },
    {
      "Sid": "AllowSendSqsUpdates",
      "Effect": "Allow",
      "Action": [
        "sqs:SendMessage"
      ],
      "Resource": "${aws_sqs_queue.xosphere_organization_inventory_data_processor_queue.arn}"
    },
    {
      "Sid": "AllowSecretManagerOperations",
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue"
	    ],
      "Resource": "${local.api_token_arn}"
    },
    {
      "Sid": "AllowKmsOperations",
      "Effect": "Allow",
      "Action": [
        "kms:Decrypt"
	    ],
      "Resource": "${local.kms_key_pattern}"
    },
    {
      "Sid": "AllowOrgKmsOperations",
      "Effect": "Allow",
      "Action": [
        "kms:Decrypt"
      ],
      "Resource": "${aws_kms_key.xosphere_mgmt_cmk.arn}"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "xosphere_organization_inventory_customer_parser_lambda_role_policy_service_linked_roles" {
  count = local.enable_org_inv_mgmt_customer ? 1 : 0
  name = "${local.lambda_function_map_xosphere_organization_inventory_customer_parser}-lambda-policy-service-linked-roles"
  role = aws_iam_role.xosphere_organization_inventory_customer_parser_lambda_role[0].id
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowLambdaServiceLinkedRole",
      "Effect": "Allow",
      "Action": [
        "iam:CreateServiceLinkedRole"
	    ],
      "Resource": [
        "arn:aws:iam::*:role/aws-service-role/lambda.amazonaws.com/*"
      ],
      "Condition": {
        "StringLike": {
          "iam:AWSServiceName": [
            "lambda.amazonaws.com"
          ]
        }
      }
    },
    {
      "Sid": "AllowLambdaServiceLinkedRolePolicies",
      "Effect": "Allow",
      "Action": [
        "iam:AttachRolePolicy",
        "iam:PutRolePolicy"
	    ],
      "Resource": "arn:aws:iam::*:role/aws-service-role/lambda.amazonaws.com/*"
    }
  ]
}
EOF
}

resource "aws_cloudwatch_log_group" "xosphere_organization_inventory_customer_parser_log_group" {
  count = local.enable_org_inv_mgmt_customer ? 1 : 0
  name = "/aws/lambda/${local.lambda_function_map_xosphere_organization_inventory_customer_parser}"
  retention_in_days = 30
}

resource "aws_lambda_permission" "xosphere_organization_inventory_customer_parser_lambda_permission_scheduler" {
  count = local.enable_org_inv_mgmt_customer ? 1 : 0
  action = "lambda:InvokeFunction"
  function_name = aws_lambda_function.xosphere_organization_inventory_customer_parser_lambda_function[0].arn
  principal = "events.amazonaws.com"
  source_arn = aws_cloudwatch_event_rule.xosphere_organization_inventory_customer_parser_schedule[0].arn
}

resource "aws_lambda_permission" "xosphere_organization_inventory_customer_parser_lambda_permission_queue" {
  count = local.enable_org_inv_mgmt_customer ? 1 : 0
  action = "lambda:InvokeFunction"
  function_name = aws_lambda_function.xosphere_organization_inventory_customer_parser_lambda_function[0].arn
  principal = "sqs.amazonaws.com"
  source_arn = aws_sqs_queue.xosphere_organization_inventory_customer_parser_queue[0].arn
}

resource "aws_cloudwatch_event_rule" "xosphere_organization_inventory_customer_parser_schedule" {
  count = local.enable_org_inv_mgmt_customer ? 1 : 0
  name = "${local.lambda_function_map_xosphere_organization_inventory_customer_parser}-schedule-event-rule"
  description = "Schedule for launching Xosphere AWS Organization Inventory Customer Parser"
  schedule_expression = "cron(${var.organization_inventory_customer_parser_schedule_expression})"
  is_enabled = true
}

resource "aws_cloudwatch_event_target" "xosphere_organization_inventory_customer_parser_schedule_target" {
  count = local.enable_org_inv_mgmt_customer ? 1 : 0
  arn = aws_lambda_function.xosphere_organization_inventory_customer_parser_lambda_function[0].arn
  rule = aws_cloudwatch_event_rule.xosphere_organization_inventory_customer_parser_schedule[0].name
  target_id = "${local.lambda_function_map_xosphere_organization_inventory_customer_parser}-schedule"
}

resource "aws_lambda_event_source_mapping" "xosphere_organization_inventory_customer_parser_event_source_mapping" {
  count = local.enable_org_inv_mgmt_customer ? 1 : 0
  batch_size = 50
  maximum_batching_window_in_seconds = 10
  enabled = true
  event_source_arn = aws_sqs_queue.xosphere_organization_inventory_customer_parser_queue[0].arn
  function_name = aws_lambda_function.xosphere_organization_inventory_customer_parser_lambda_function[0].arn
  depends_on = [ aws_iam_role.xosphere_organization_inventory_customer_parser_lambda_role[0] ]
}

resource "aws_sqs_queue" "xosphere_organization_inventory_customer_parser_dl_queue" {
  count = local.enable_org_inv_mgmt_customer ? 1 : 0
  name = "xosphere-instance-orchestrator-org-inv-customer-parser-launch-dlq"
  visibility_timeout_seconds = 1020
  kms_master_key_id = aws_kms_key.xosphere_mgmt_cmk.id
}

resource "aws_sqs_queue" "xosphere_organization_inventory_customer_parser_queue" {
  count = local.enable_org_inv_mgmt_customer ? 1 : 0
  name = "xosphere-instance-orchestrator-org-inv-customer-parser-launch"
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.xosphere_organization_inventory_customer_parser_dl_queue[0].arn
    maxReceiveCount = 5
  })
  visibility_timeout_seconds = 1020
  kms_master_key_id = aws_kms_key.xosphere_mgmt_cmk.id
}

resource "aws_sqs_queue_policy" "xosphere_organization_inventory_customer_parser_queue_policy" {
  count = local.enable_org_inv_mgmt_customer ? 1 : 0
  queue_url = aws_sqs_queue.xosphere_organization_inventory_customer_parser_queue[0].id

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowLambdaUpdateReadSqs",
      "Effect": "Allow",
      "Action": [
        "sqs:ChangeMessageVisibility",
        "sqs:DeleteMessage",
        "sqs:GetQueueAttributes",
        "sqs:ReceiveMessage",
        "sqs:GetQueueUrl"
	    ],
      "Principal": {
        "AWS": "${aws_iam_role.xosphere_organization_inventory_customer_parser_lambda_role[0].arn}"
      },
      "Resource": "${aws_sqs_queue.xosphere_organization_inventory_customer_parser_queue[0].arn}"
    },
    {
      "Sid": "AllowSendFromS3",
      "Effect": "Allow",
      "Principal": {
        "Service": "s3.amazonaws.com"
      },
      "Action": "SQS:SendMessage",
      "Resource": "${aws_sqs_queue.xosphere_organization_inventory_customer_parser_queue[0].arn}",
      "Condition": {
        "ArnEquals": {
%{ if var.customer_inventory_bucket_name_override == null }
          "aws:SourceArn": "arn:aws:s3:::var.customer_inventory_bucket_name_override"
%{ else }
          %{ if false } # can't use !GetAtt CustomerInventoryBucket.Arn because of circular reference %{ endif }
          "aws:SourceArn": "arn:aws:s3:::xosphere-io-mgmt-${data.aws_region.current.name}-${data.aws_caller_identity.current.account_id}-inventory"
%{ endif }
        },
        "StringEquals": {
          "aws:SourceAccount": "${data.aws_caller_identity.current.account_id}"
        }
      }
    }
  ]
}
EOF
}

resource "aws_sqs_queue" "xosphere_organization_inventory_realtime_updates_dl_queue" {
  count = local.enable_org_inv_mgmt_xosphere ? 1 : 0
  name = "xosphere-instance-orchestrator-org-inv-realtime-updates-dlq"
  visibility_timeout_seconds = 1020
  kms_master_key_id = aws_kms_key.xosphere_mgmt_cmk.id
}

resource "aws_sqs_queue" "xosphere_organization_inventory_realtime_updates_queue" {
  count = local.enable_org_inv_mgmt_xosphere ? 1 : 0
  name = "xosphere-instance-orchestrator-org-inv-realtime-updates-queue"
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.xosphere_organization_inventory_realtime_updates_dl_queue[0].arn
    maxReceiveCount = 5
  })
  visibility_timeout_seconds = 1020
  kms_master_key_id = aws_kms_key.xosphere_mgmt_cmk.id
}

resource "aws_sqs_queue_policy" "xosphere_organization_inventory_realtime_updates_queue_policy" {
  count = local.enable_org_inv_mgmt_xosphere ? 1 : 0
  queue_url = aws_sqs_queue.xosphere_organization_inventory_realtime_updates_queue[0].id

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowSendSqsUpdates",
      "Effect": "Allow",
      "Principal": {
        "Service": "events.amazonaws.com"
      },
      "Action": "sqs:SendMessage",
      "Resource": "${aws_sqs_queue.xosphere_organization_inventory_realtime_updates_queue[0].arn}",
      "Condition": {
        "StringEquals": {
          "aws:SourceArn": "${aws_cloudwatch_event_rule.xosphere_organization_inventory_relayer_rule[0].arn}"
        }
      }
    }
  ]
}
EOF
}

resource "aws_sqs_queue" "xosphere_organization_inventory_report_request_dl_queue" {
  count = local.enable_org_inv_mgmt_xosphere ? 1 : 0
  name = "xosphere-instance-orchestrator-org-inv-report-request-dlq"
  visibility_timeout_seconds = 1020
  kms_master_key_id = aws_kms_key.xosphere_mgmt_cmk.id
}

resource "aws_sqs_queue" "xosphere_organization_inventory_report_request_queue" {
  count = local.enable_org_inv_mgmt_xosphere ? 1 : 0
  name = "xosphere-instance-orchestrator-org-inv-report-request-queue"
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.xosphere_organization_inventory_report_request_dl_queue[0].arn
    maxReceiveCount = 5
  })
  visibility_timeout_seconds = 1020
  kms_master_key_id = aws_kms_key.xosphere_mgmt_cmk.id
}

resource "aws_sqs_queue_policy" "xosphere_organization_inventory_report_request_queue_policy" {
  count = local.enable_org_inv_mgmt_xosphere ? 1 : 0
  queue_url = aws_sqs_queue.xosphere_organization_inventory_report_request_queue[0].id

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowSendSqsUpdates",
      "Effect": "Allow",
      "Principal": {
        "AWS": "${aws_iam_role.xosphere_organization_inventory_baseline_requester_lambda_role[0].arn}"
      },
      "Action": "sqs:SendMessage",
      "Resource": "${aws_sqs_queue.xosphere_organization_inventory_report_request_queue[0].arn}"
    }
  ]
}
EOF
}

resource "aws_sqs_queue" "xosphere_organization_inventory_report_submission_dl_queue" {
  count = local.enable_org_inv_mgmt_xosphere ? 1 : 0
  name = "xosphere-instance-orchestrator-org-inv-report-submission-dlq"
  visibility_timeout_seconds = 1020
  kms_master_key_id = aws_kms_key.xosphere_mgmt_cmk.id
}

resource "aws_sqs_queue" "xosphere_organization_inventory_report_submission_queue" {
  count = local.enable_org_inv_mgmt_xosphere ? 1 : 0
  name = "xosphere-instance-orchestrator-org-inv-report-submission-queue"
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.xosphere_organization_inventory_report_submission_dl_queue[0].arn
    maxReceiveCount = 5
  })
  visibility_timeout_seconds = 1020
  kms_master_key_id = aws_kms_key.xosphere_mgmt_cmk.id
}

resource "aws_sqs_queue_policy" "xosphere_organization_inventory_report_submission_queue_policy" {
  count = local.enable_org_inv_mgmt_xosphere ? 1 : 0
  queue_url = aws_sqs_queue.xosphere_organization_inventory_report_submission_queue[0].id

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowSendSqsUpdates",
      "Effect": "Allow",
      "Principal": {
        "AWS": "${aws_iam_role.xosphere_organization_inventory_baseline_reporter_lambda_role[0].arn}"
      },
      "Action": "sqs:SendMessage",
      "Resource": "${aws_sqs_queue.xosphere_organization_inventory_report_submission_queue[0].arn}"
    }
  ]
}
EOF
}

resource "aws_cloudwatch_event_rule" "xosphere_organization_inventory_relayer_rule" {
  count = local.enable_org_inv_mgmt_xosphere ? 1 : 0
  name = "${local.well_known_names_xosphere_organization_inventory_realtime_updates_relayer}-event-rule"
  description = "Relayed CloudWatch Event trigger for EC2 state change"
  event_bus_name = aws_cloudwatch_event_bus.xosphere_organization_inventory_realtime_updates_event_bus[0].name
  event_pattern = <<PATTERN
{
  "source": [
    "aws.ec2"
  ],
  "detail-type": [
    "EC2 Instance State-change Notification"
  ],
  "detail": {
    "state": [
      "pending",
      "terminated",
      "stopped"
    ]
  }
}
PATTERN
  is_enabled = true
}

resource "aws_cloudwatch_event_target" "xosphere_organization_inventory_relayer_target" {
  count = local.enable_org_inv_mgmt_xosphere ? 1 : 0
  arn = aws_sqs_queue.xosphere_organization_inventory_realtime_updates_queue[0].arn
  event_bus_name = aws_cloudwatch_event_rule.xosphere_organization_inventory_relayer_rule[0].event_bus_name
  rule = aws_cloudwatch_event_rule.xosphere_organization_inventory_relayer_rule[0].name
  target_id = "${local.well_known_names_xosphere_organization_inventory_realtime_updates_relayer}-event-rule-target"
  dead_letter_config {
    arn = aws_sqs_queue.xosphere_organization_inventory_realtime_updates_dl_queue[0].arn
  }
}

resource "aws_cloudwatch_event_bus" "xosphere_organization_inventory_realtime_updates_event_bus" {
  count = local.enable_org_inv_mgmt_xosphere ? 1 : 0
  name = local.well_known_names_xosphere_organization_inventory_realtime_updates_event_bus_name
}

resource "aws_cloudwatch_event_bus_policy" "xosphere_organization_inventory_realtime_updates_event_bus_policy" {
  count = local.enable_org_inv_mgmt_xosphere ? 1 : 0
  event_bus_name = aws_cloudwatch_event_bus.xosphere_organization_inventory_realtime_updates_event_bus[0].name
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "InvCollectorRealtimePublish",
      "Effect": "Allow",
      "Principal": {
          "AWS": "*"
      },
      "Action": "events:PutEvents",
      "Resource": "${aws_cloudwatch_event_bus.xosphere_organization_inventory_realtime_updates_event_bus[0].arn}",
      "Condition": {
        "StringEquals": {
          "aws:PrincipalOrgID": "${var.aws_organization_id}" %{ if false } # should use a pseudo parameter, but AWS doesn't yet provide one.  https://github.com/aws-cloudformation/cloudformation-coverage-roadmap/issues/160 %{ endif }
        }
        ,
        "ArnLike": {
          "aws:PrincipalArn": "${join("", ["arn:aws:iam::*:role/", local.well_known_names_xosphere_organization_inventory_realtime_updates_submitter, "-assume-role"])}"
        }
      }
    }
  ]
}
  EOF
}

resource "aws_iam_role" "xosphere_organization_support_access_role" {
  count = var.enable_auto_support ? 1 : 0
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": {
    "Sid": "AllowXosphereSupportTrustPolicy",
    "Action": [ "sts:AssumeRole" ],
    "Effect": "Allow",
    "Principal": {
      "AWS": "770759415832"
    },
    "Condition": {
      "StringEquals": {
        "sts:ExternalId": "${var.customer_id}"
      }
    }
  }
}
EOF
  managed_policy_arns = [ ]
  path = "/"
  name = "xosphere-org-auto-support-role"
}

resource "aws_iam_role_policy" "xosphere_organization_support_access_role_policy" {
  count = var.enable_auto_support ? 1 : 0
  name = "xosphere-org-auto-support-policy"
  role = aws_iam_role.xosphere_organization_support_access_role[0].id
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowReadOperationsOnXosphereLogGroups",
      "Effect": "Allow",
      "Action": [
        "logs:DescribeLogStreams",
        "logs:FilterLogEvents",
        "logs:GetLogEvents"
	    ],
      "Resource": [
        "arn:aws:logs:*:*:log-group:/aws/lambda/xosphere-*",
        "arn:aws:logs:*:*:log-group:/aws/lambda/xosphere-*:log-stream:*"
      ]
    },  
    {
      "Sid": "AllowReadOperationsOnXosphereManagedInstancesAndAsgs",
      "Effect": "Allow",
      "Action": [
        "ec2:Describe*",
        "autoscaling:Describe*"
	    ],
      "Resource": "*"
    }
  ]
}
EOF
}
