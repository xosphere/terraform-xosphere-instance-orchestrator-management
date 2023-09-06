# Xosphere Instance Orchestration configuration
variable "customer_id" {
  description = "Customer ID provided by Xosphere"  
}

variable "xo_account_id" {
  default = "143723790106"
}

variable "aws_organization_id" {
  description = "The AWS Organization ID"
}

variable "aws_organization_mgmt_account_id" {
  description = "The AWS Account ID of the AWS Organization Management account"
}

variable "ri_purchasing_accounts" {
  type = list(string)
  description = "List of all AWS accounts that purchase Reserved Instances"
}

variable "enable_auto_support" {
  description = "Enable Auto Support"
  type = bool
  default = true
}

variable "organization_ri_data_gatherer_schedule_expression" {
  description = "Cron expression for the AWS Organization RI Data Gatherer schedule"
  default = "0 * * * ? *"
}

variable "organization_inventory_data_processor_schedule_expression" {
  description = "Cron expression for the AWS Organization Inventory Data Processor schedule"
  default = "0/1 * * * ? *"
}

variable "organization_ri_sub_account_requester_schedule_expression" {
  description = "Cron expression for the Instance Orchestrator RI sub-account requester schedule"
  default = "0 * * * ? *"
}

variable "organization_inventory_management" {
  description = "Enable AWS Organization Inventory management. Default as 'xosphere'."
  default = "xosphere"
  validation {
    condition     = contains(["none", "xosphere", "customer-provided"], var.organization_inventory_management)
    error_message = "Invalid input, options: \"none\",\"xosphere\",\"customer-provided\"."
  }
}

variable "xosphere_customer_inventory_s3_file_path" {
  description = "Customer inventory path in S3 bucket. Required."
  default = "/org-data/inventory.json.gz"
}

variable "xosphere_customer_inventory_gzip_compressed" {
  description = "Customer inventory is gzip compressed. Default as true."
  type = bool
  default = true
}

variable "xosphere_customer_inventory_enable_versioning" {
  description = "If customer inventory bucket has versioning enabled. Default as true."
  type = bool
  default = true
}

variable "xosphere_customer_inventory_replication_role_arn" {
  description = "Customer arn for uploading inventory files"
  default = ""
}

variable "xosphere_customer_inventory_cmk_custom_tag_name" {
  description = "Customer tag name for inventory CMK"
  default = null
}

variable "xosphere_customer_inventory_cmk_custom_tag_value" {
  description = "Customer tag value for inventory CMK"
  default = null
}

variable "create_logging_buckets" {
  description = "If logging buckets should be created for S3 data buckets.  Default as false."
  type = bool
  default = false
}

variable "enable_enhanced_security" {
  description = "Enable enhanced security restrictions.  Default as false."
  type = bool
  default = false
}

variable "organization_inventory_baseline_requester_schedule_expression" {
  description = "Cron expression for the AWS Organization Inventory Baseline Requester schedule"
  default = "0/15 * * * ? *"
}

variable "organization_inventory_customer_parser_schedule_expression" {
  description = "Cron expression for the AWS Organization Inventory Customer Parser schedule"
  default = "0/1 * * * ? *"
}


































## for internal testing only
variable "logging_bucket_name_override" {
  description = "An explicit name to use"
  default = null
}

variable "organization_data_access_logs_bucket_name_override" {
  description = "An explicit name to use"
  default = null
}

variable "organization_ri_sub_account_data_bucket_name_override" {
  description = "An explicit name to use"
  default = null
}

variable "organization_ri_sub_account_data_access_logs_bucket_name_override" {
  description = "An explicit name to use"
  default = null
}

variable "organization_data_bucket_name_override" {
  description = "An explicit name to use"
  default = null
}

variable "customer_inventory_bucket_name_override" {
  description = "An explicit name to use"
  default = null
}

variable "secretsmanager_arn_override" {
  description = "An explicit name to use"
  default = null
}
