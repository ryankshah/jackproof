package posture

const scpSnippet = `Service control policy that denies Bedrock in accounts that do not need it. Attach it to those accounts or their organizational unit:

{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyModelServices",
      "Effect": "Deny",
      "Action": [
        "bedrock:*"
      ],
      "Resource": "*"
    }
  ]
}`

const orgPolicySnippet = `Organization policy that denies the model services in projects that do not need them:

name: organizations/ORGANIZATION_ID/policies/gcp.restrictServiceUsage
spec:
  rules:
    - values:
        deniedValues:
          - aiplatform.googleapis.com
          - generativelanguage.googleapis.com`

const azurePolicySnippet = `Azure Policy rule that denies Azure OpenAI accounts in scopes that do not need them:

{
  "if": {
    "allOf": [
      { "field": "type", "equals": "Microsoft.CognitiveServices/accounts" },
      { "field": "kind", "equals": "OpenAI" }
    ]
  },
  "then": { "effect": "deny" }
}`

const awsBudgetSnippet = `Budget that alerts on Bedrock spend:

resource "aws_budgets_budget" "bedrock" {
  name         = "bedrock-monthly"
  budget_type  = "COST"
  limit_amount = "100"
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  cost_filter {
    name   = "Service"
    values = ["Amazon Bedrock"]
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = ["security@example.com"]
  }
}`

const gcpBudgetSnippet = `Budget that alerts on project spend, including Vertex AI:

resource "google_billing_budget" "models" {
  billing_account = var.billing_account
  display_name    = "model-spend"

  amount {
    specified_amount {
      currency_code = "USD"
      units         = "100"
    }
  }

  threshold_rules {
    threshold_percent = 0.8
  }
}`

const azureBudgetSnippet = `Budget that alerts on subscription spend, including Azure OpenAI:

resource "azurerm_consumption_budget_subscription" "models" {
  name            = "model-spend"
  subscription_id = data.azurerm_subscription.current.id
  amount          = 100
  time_grain      = "Monthly"

  time_period {
    start_date = "2026-01-01T00:00:00Z"
  }

  notification {
    enabled        = true
    threshold      = 80
    operator       = "GreaterThan"
    contact_emails = ["security@example.com"]
  }
}`

const awsLoggingSnippet = `Invocation logging configuration:

resource "aws_bedrock_model_invocation_logging_configuration" "this" {
  logging_config {
    text_data_delivery_enabled      = true
    image_data_delivery_enabled     = true
    embedding_data_delivery_enabled = true

    cloudwatch_config {
      log_group_name = aws_cloudwatch_log_group.bedrock.name
      role_arn       = aws_iam_role.bedrock_logging.arn
    }
  }
}`

const gcpLoggingSnippet = `Data Access audit logs for Vertex AI:

resource "google_project_iam_audit_config" "vertex" {
  project = var.project
  service = "aiplatform.googleapis.com"

  audit_log_config {
    log_type = "DATA_READ"
  }

  audit_log_config {
    log_type = "DATA_WRITE"
  }
}`

const azureLoggingSnippet = `Diagnostic setting for the Azure OpenAI account:

resource "azurerm_monitor_diagnostic_setting" "openai" {
  name                       = "openai-audit"
  target_resource_id         = azurerm_cognitive_account.openai.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log {
    category = "Audit"
  }
}`

const awsQuotaSnippet = `Lower the quota to what the workload needs. Look up the quota code for the model in Service Quotas:

resource "aws_servicequotas_service_quota" "bedrock" {
  service_code = "bedrock"
  quota_code   = "L-XXXXXXXX"
  value        = 100
}`

const gcpQuotaSnippet = `Override the consumer quota for the model service:

resource "google_service_usage_consumer_quota_override" "vertex" {
  project        = var.project
  service        = "aiplatform.googleapis.com"
  metric         = urlencode("aiplatform.googleapis.com/METRIC_NAME")
  limit          = urlencode("/min/project")
  override_value = "100"
  force          = true
}`

const azureQuotaSnippet = `Set the deployment capacity to what the workload needs:

resource "azurerm_cognitive_deployment" "chat" {
  name                 = "chat"
  cognitive_account_id = azurerm_cognitive_account.openai.id

  model {
    format  = "OpenAI"
    name    = "MODEL_NAME"
    version = "MODEL_VERSION"
  }

  sku {
    name     = "Standard"
    capacity = 10
  }
}`

const awsInvokeSnippet = `Limit invocation to the models the workload uses:

{
  "Effect": "Allow",
  "Action": [
    "bedrock:InvokeModel",
    "bedrock:InvokeModelWithResponseStream"
  ],
  "Resource": [
    "arn:aws:bedrock:REGION::foundation-model/MODEL_ID"
  ]
}`

const awsKeyDenySnippet = `Deny key creation for model-capable users with a permissions boundary or an SCP:

{
  "Effect": "Deny",
  "Action": "iam:CreateAccessKey",
  "Resource": "arn:aws:iam::ACCOUNT_ID:user/MODEL_USER_NAME"
}`

func budgetSnippet(cloud Cloud) string {
	switch cloud {
	case CloudAWS:
		return awsBudgetSnippet
	case CloudGCP:
		return gcpBudgetSnippet
	}
	return azureBudgetSnippet
}

func loggingSnippet(cloud Cloud) string {
	switch cloud {
	case CloudAWS:
		return awsLoggingSnippet
	case CloudGCP:
		return gcpLoggingSnippet
	}
	return azureLoggingSnippet
}

func quotaSnippet(cloud Cloud) string {
	switch cloud {
	case CloudAWS:
		return awsQuotaSnippet
	case CloudGCP:
		return gcpQuotaSnippet
	}
	return azureQuotaSnippet
}

func guardrailSnippet(cloud Cloud) string {
	switch cloud {
	case CloudAWS:
		return scpSnippet
	case CloudGCP:
		return orgPolicySnippet
	}
	return azurePolicySnippet
}

const gcpKeyDenySnippet = `Organization policy that blocks service account key creation:

name: organizations/ORGANIZATION_ID/policies/iam.disableServiceAccountKeyCreation
spec:
  rules:
    - enforce: true`

func keyDenySnippet(cloud Cloud) string {
	if cloud == CloudGCP {
		return gcpKeyDenySnippet
	}
	return awsKeyDenySnippet
}
