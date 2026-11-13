package posture

import (
	"strings"
	"testing"

	"github.com/ryankshah/jackproof/internal/config"
	"github.com/ryankshah/jackproof/internal/finding"
	"github.com/ryankshah/jackproof/internal/rules"
)

type result struct {
	findings []finding.Finding
	infra    *Infra
}

func runPosture(t *testing.T, configYAML string, files map[string]string) result {
	t.Helper()
	cfg, err := config.Parse([]byte(configYAML))
	if err != nil {
		t.Fatal(err)
	}
	ruleSet, err := rules.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	knowledge, err := LoadKnowledge()
	if err != nil {
		t.Fatal(err)
	}
	var sources []Source
	for name, content := range files {
		sources = append(sources, Source{Path: name, Data: []byte(content)})
	}
	infra := Extract(sources, cfg, knowledge)
	findings, err := Analyze(infra, sources, cfg, ruleSet, knowledge)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if err := f.Validate(); err != nil {
			t.Errorf("finding %s (%s) is invalid: %v", f.ID, f.Rule, err)
		}
		if f.Module != finding.ModulePosture {
			t.Errorf("finding %s has module %s", f.ID, f.Module)
		}
	}
	return result{findings: findings, infra: infra}
}

func (r result) rule(id string) []finding.Finding {
	var matched []finding.Finding
	for _, f := range r.findings {
		if f.Rule == id {
			matched = append(matched, f)
		}
	}
	return matched
}

func (r result) titled(id, fragment string) (finding.Finding, bool) {
	for _, f := range r.rule(id) {
		if strings.Contains(f.Title, fragment) {
			return f, true
		}
	}
	return finding.Finding{}, false
}

const environments = "environments:\n  prod: [\"prod/**\"]\n  ml: [\"ml/**\"]\nexpected_providers:\n  ml: [bedrock]\n  prod: []\n"

func enablerPolicy(name string) string {
	return `
resource "aws_iam_role" "` + name + `" {
  name = "` + name + `"
}

resource "aws_iam_role_policy" "` + name + `" {
  role   = aws_iam_role.` + name + `.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["bedrock:PutFoundationModelEntitlement", "aws-marketplace:Subscribe"]
      Resource = "*"
    }]
  })
}
`
}

func TestEnableModelAccessDependsOnExpectedProviders(t *testing.T) {
	tests := []struct {
		name           string
		path           string
		wantFindings   int
		wantConfidence finding.Confidence
		wantFlag       finding.Flag
	}{
		{"unexpected environment", "prod/iam.tf", 1, finding.ConfidenceHigh, finding.FlagConfigImplied},
		{"expected environment", "ml/iam.tf", 0, "", ""},
		{"unmapped path", "other/iam.tf", 1, finding.ConfidenceMedium, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := runPosture(t, environments, map[string]string{tt.path: enablerPolicy("deployer")})
			found := r.rule("JP-POS-001")
			if len(found) != tt.wantFindings {
				t.Fatalf("JP-POS-001 count = %d, want %d: %+v", len(found), tt.wantFindings, found)
			}
			if tt.wantFindings == 0 {
				return
			}
			f := found[0]
			if f.Confidence != tt.wantConfidence {
				t.Errorf("confidence = %s, want %s", f.Confidence, tt.wantConfidence)
			}
			hasFlag := false
			for _, flag := range f.Flags {
				if flag == tt.wantFlag {
					hasFlag = true
				}
			}
			if tt.wantFlag != "" && !hasFlag {
				t.Errorf("flags = %v, want %s", f.Flags, tt.wantFlag)
			}
			if tt.wantFlag == "" && len(f.Unproven) == 0 {
				t.Error("an unconfigured environment must state what is unproven")
			}
			if !strings.Contains(f.Remediation, `"Effect": "Deny"`) {
				t.Errorf("remediation lacks the guardrail snippet: %s", f.Remediation)
			}
			if f.Evidence[0].StartLine < 1 || f.Evidence[0].Excerpt == "" {
				t.Errorf("evidence = %+v", f.Evidence)
			}
		})
	}
}

func TestAdministratorsAreExcluded(t *testing.T) {
	files := map[string]string{"prod/iam.tf": `
resource "aws_iam_role" "platform_admin" {
  name = "platform-admin"
}

resource "aws_iam_role_policy_attachment" "admin" {
  role       = aws_iam_role.platform_admin.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
`}
	r := runPosture(t, "environments:\n  prod: [\"prod/**\"]\nexpected_providers:\n  prod: []\n", files)
	for _, id := range []string{"JP-POS-001", "JP-POS-003", "JP-POS-006", "JP-POS-007"} {
		if got := len(r.rule(id)); got != 0 {
			t.Errorf("%s reported %d findings for an administrator", id, got)
		}
	}
	if len(r.infra.Grants) != 1 || !r.infra.Grants[0].Admin {
		t.Errorf("grants = %+v", r.infra.Grants)
	}
}

func TestWildcardInvokeAndLoggingToggle(t *testing.T) {
	files := map[string]string{"ml/chat.tf": `
resource "aws_iam_role" "chat" {
  name = "chat-service"
}

data "aws_iam_policy_document" "chat" {
  statement {
    actions   = ["bedrock:InvokeModel", "bedrock:PutModelInvocationLoggingConfiguration"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "chat" {
  role   = aws_iam_role.chat.id
  policy = data.aws_iam_policy_document.chat.json
}

resource "aws_iam_role" "narrow" {
  name = "narrow-service"
}

resource "aws_iam_role_policy" "narrow" {
  role   = aws_iam_role.narrow.id
  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = ["bedrock:InvokeModel"]
      Resource = ["arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3-haiku"]
    }]
  })
}
`}
	r := runPosture(t, environments, files)
	wildcard := r.rule("JP-POS-006")
	if len(wildcard) != 1 || !strings.Contains(wildcard[0].Title, "chat-service") || !strings.Contains(wildcard[0].Title, "wildcard resource") {
		t.Fatalf("JP-POS-006 = %+v", wildcard)
	}
	if wildcard[0].Confidence != finding.ConfidenceHigh || !strings.Contains(wildcard[0].Remediation, "foundation-model/MODEL_ID") {
		t.Errorf("wildcard finding = %+v", wildcard[0])
	}
	toggle, ok := r.titled("JP-POS-003", "can change or delete")
	if !ok || !strings.Contains(toggle.Title, "chat-service") {
		t.Errorf("logging toggle finding = %+v", r.rule("JP-POS-003"))
	}
	if len(toggle.Evidence) != 2 || toggle.Evidence[0].Path != "ml/chat.tf" {
		t.Errorf("evidence = %+v", toggle.Evidence)
	}
	if got := len(r.rule("JP-POS-001")); got != 0 {
		t.Errorf("an environment that expects bedrock produced %d JP-POS-001 findings", got)
	}
}

func TestBedrockWildcardActionIsFlaggedAndEnables(t *testing.T) {
	files := map[string]string{"prod/app.tf": `
resource "aws_iam_role" "app" {
  name = "app"
}

resource "aws_iam_role_policy_attachment" "bedrock" {
  role       = aws_iam_role.app.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonBedrockFullAccess"
}
`}
	r := runPosture(t, environments, files)
	if _, ok := r.titled("JP-POS-001", "app can enable Amazon Bedrock"); !ok {
		t.Errorf("JP-POS-001 = %+v", r.rule("JP-POS-001"))
	}
	if _, ok := r.titled("JP-POS-006", "wildcard action"); !ok {
		t.Errorf("JP-POS-006 = %+v", r.rule("JP-POS-006"))
	}
	if _, ok := r.titled("JP-POS-003", "can change or delete"); !ok {
		t.Errorf("JP-POS-003 = %+v", r.rule("JP-POS-003"))
	}
}

func TestUnattachedPolicyIsReportedAsIncomplete(t *testing.T) {
	files := map[string]string{"ml/policy.tf": `
resource "aws_iam_policy" "open" {
  name   = "open"
  policy = jsonencode({
    Statement = [{ Effect = "Allow", Action = "bedrock:*", Resource = "*" }]
  })
}
`}
	r := runPosture(t, environments, files)
	found := r.rule("JP-POS-006")
	if len(found) != 1 || len(found[0].Unproven) == 0 || found[0].Flags[len(found[0].Flags)-1] != finding.FlagIncomplete {
		t.Fatalf("findings = %+v", found)
	}
}

func TestKeyCreationForModelCapablePrincipals(t *testing.T) {
	files := map[string]string{"ml/keys.tf": `
resource "aws_iam_user" "llm" {
  name = "llm-batch"
}

resource "aws_iam_user_policy" "llm" {
  user   = aws_iam_user.llm.name
  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = ["bedrock:InvokeModel"]
      Resource = ["arn:aws:bedrock:us-east-1::foundation-model/m"]
    }]
  })
}

resource "aws_iam_role" "ops" {
  name = "ops-bot"
}

resource "aws_iam_role_policy" "ops" {
  role   = aws_iam_role.ops.id
  policy = jsonencode({
    Statement = [{ Effect = "Allow", Action = ["iam:CreateAccessKey"], Resource = "*" }]
  })
}

resource "aws_iam_role" "scoped" {
  name = "scoped-bot"
}

resource "aws_iam_role_policy" "scoped" {
  role   = aws_iam_role.scoped.id
  policy = jsonencode({
    Statement = [{ Effect = "Allow", Action = ["iam:CreateAccessKey"], Resource = "arn:aws:iam::123456789012:user/someone-else" }]
  })
}
`}
	r := runPosture(t, environments, files)
	found := r.rule("JP-POS-007")
	if len(found) != 1 || !strings.Contains(found[0].Title, "ops-bot") {
		t.Fatalf("JP-POS-007 = %+v", found)
	}
	noModels := runPosture(t, environments, map[string]string{"ml/keys.tf": `
resource "aws_iam_role" "ops" {
  name = "ops-bot"
}

resource "aws_iam_role_policy" "ops" {
  role   = aws_iam_role.ops.id
  policy = jsonencode({
    Statement = [{ Effect = "Allow", Action = ["iam:CreateAccessKey"], Resource = "*" }]
  })
}
`})
	if got := len(noModels.rule("JP-POS-007")); got != 0 {
		t.Errorf("key creation without any model-capable principal produced %d findings", got)
	}
}

func TestGuardrailBudgetLoggingAndQuotaControls(t *testing.T) {
	base := `
resource "aws_iam_role" "chat" {
  name = "chat-service"
}

resource "aws_bedrockagent_agent" "assistant" {
  agent_name = "assistant"
}
`
	scp := `
resource "aws_organizations_policy" "deny_bedrock" {
  name    = "deny-bedrock"
  content = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Deny", Action = ["bedrock:*"], Resource = "*" }]
  })
}
`
	otherScp := `
resource "aws_organizations_policy" "deny_s3" {
  name    = "deny-s3"
  content = jsonencode({
    Statement = [{ Effect = "Deny", Action = ["s3:DeleteBucket"], Resource = "*" }]
  })
}
`
	budget := func(filter string) string {
		return `
resource "aws_budgets_budget" "spend" {
  name         = "spend"
  budget_type  = "COST"
  limit_amount = "100"
  limit_unit   = "USD"
  time_unit    = "MONTHLY"
  ` + filter + `
}
`
	}
	tests := []struct {
		name       string
		extra      string
		rule       string
		wantFinds  int
		wantInText string
	}{
		{"no guardrail", "", "JP-POS-002", 1, "service control policy"},
		{"guardrail present", scp, "JP-POS-002", 0, ""},
		{"unrelated service control policy", otherScp, "JP-POS-002", 1, ""},
		{"no budget", "", "JP-POS-004", 1, "aws_budgets_budget"},
		{"unfiltered budget", budget(""), "JP-POS-004", 0, ""},
		{"bedrock budget", budget("cost_filter {\n    name   = \"Service\"\n    values = [\"Amazon Bedrock\"]\n  }"), "JP-POS-004", 0, ""},
		{"unrelated budget", budget("cost_filter {\n    name   = \"Service\"\n    values = [\"Amazon S3\"]\n  }"), "JP-POS-004", 1, ""},
		{"no logging", "", "JP-POS-003", 1, "aws_bedrock_model_invocation_logging_configuration"},
		{"logging on", "resource \"aws_bedrock_model_invocation_logging_configuration\" \"this\" {\n  logging_config {\n    text_data_delivery_enabled = true\n    image_data_delivery_enabled = true\n    embedding_data_delivery_enabled = true\n  }\n}\n", "JP-POS-003", 0, ""},
		{"logging delivery off", "resource \"aws_bedrock_model_invocation_logging_configuration\" \"this\" {\n  logging_config {\n    text_data_delivery_enabled = false\n    image_data_delivery_enabled = false\n    embedding_data_delivery_enabled = false\n  }\n}\n", "JP-POS-003", 1, "turned off"},
		{"no quota", "", "JP-POS-005", 1, "aws_servicequotas_service_quota"},
		{"quota set", "resource \"aws_servicequotas_service_quota\" \"bedrock\" {\n  service_code = \"bedrock\"\n  quota_code   = \"L-1\"\n  value        = 10\n}\n", "JP-POS-005", 0, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := runPosture(t, "", map[string]string{"infra/main.tf": base + tt.extra})
			found := r.rule(tt.rule)
			var related []finding.Finding
			for _, f := range found {
				if !strings.Contains(f.Title, "can change or delete") {
					related = append(related, f)
				}
			}
			if len(related) != tt.wantFinds {
				t.Fatalf("%s count = %d, want %d: %+v", tt.rule, len(related), tt.wantFinds, related)
			}
			if tt.wantFinds == 1 && tt.wantInText != "" {
				combined := strings.ToLower(related[0].Title + related[0].Remediation)
				if !strings.Contains(combined, strings.ToLower(tt.wantInText)) {
					t.Errorf("finding lacks %q: %s", tt.wantInText, combined)
				}
				if !containsFlag(related[0], finding.FlagIncomplete) && tt.name != "logging delivery off" {
					t.Errorf("flags = %v, want incomplete", related[0].Flags)
				}
			}
		})
	}
}

func containsFlag(f finding.Finding, flag finding.Flag) bool {
	for _, candidate := range f.Flags {
		if candidate == flag {
			return true
		}
	}
	return false
}

func TestNoCloudResourcesProduceNoControlFindings(t *testing.T) {
	r := runPosture(t, "", map[string]string{"main.tf": "variable \"x\" {}\n", "notes.txt": "x"})
	if len(r.findings) != 0 {
		t.Errorf("findings = %+v", r.findings)
	}
	if r.infra.Coverage.FilesScanned["terraform"] != 1 {
		t.Errorf("coverage = %+v", r.infra.Coverage)
	}
}

func TestGuardrailSkippedWhereModelsAreExpectedEverywhere(t *testing.T) {
	cfg := "environments:\n  ml: [\"**\"]\nexpected_providers:\n  ml: [bedrock]\n"
	r := runPosture(t, cfg, map[string]string{"main.tf": "resource \"aws_iam_role\" \"x\" {\n  name = \"x\"\n}\n"})
	if got := len(r.rule("JP-POS-002")); got != 0 {
		t.Errorf("JP-POS-002 count = %d, want 0", got)
	}
}

func TestGCP(t *testing.T) {
	files := map[string]string{"prod/gcp.tf": `
resource "google_service_account" "batch" {
  account_id = "batch"
}

resource "google_service_account" "ops" {
  account_id = "ops"
}

resource "google_project_service" "vertex" {
  service = "aiplatform.googleapis.com"
}

resource "google_project_iam_member" "enabler" {
  project = "p"
  role    = "roles/serviceusage.serviceUsageAdmin"
  member  = "serviceAccount:${google_service_account.ops.email}"
}

resource "google_project_iam_member" "owner" {
  project = "p"
  role    = "roles/owner"
  member  = "serviceAccount:${google_service_account.batch.email}"
}

resource "google_project_iam_member" "predict" {
  project = "p"
  role    = "roles/aiplatform.user"
  member  = "serviceAccount:${google_service_account.batch.email}"
}

resource "google_project_iam_member" "keys" {
  project = "p"
  role    = "roles/iam.serviceAccountKeyAdmin"
  member  = "serviceAccount:${google_service_account.ops.email}"
}

resource "google_project_iam_custom_role" "mine" {
  role_id     = "mine"
  title       = "Mine"
  permissions = ["serviceusage.services.enable"]
}

resource "google_project_iam_member" "custom" {
  project = "p"
  role    = google_project_iam_custom_role.mine.id
  member  = "user:dev@example.com"
}
`}
	r := runPosture(t, environments, files)
	if _, ok := r.titled("JP-POS-001", "can enable Gemini API and Vertex AI"); !ok {
		t.Errorf("JP-POS-001 = %+v", titles(r.rule("JP-POS-001")))
	}
	if len(r.rule("JP-POS-001")) < 3 {
		t.Errorf("expected enable findings for the usage admin, the owner and the custom role, got %+v", titles(r.rule("JP-POS-001")))
	}
	if _, ok := r.titled("JP-POS-006", "roles/owner"); !ok {
		t.Errorf("JP-POS-006 = %+v", titles(r.rule("JP-POS-006")))
	}
	if keys := r.rule("JP-POS-007"); len(keys) != 2 || !strings.Contains(keys[0].Remediation, "iam.disableServiceAccountKeyCreation") {
		t.Errorf("JP-POS-007 = %+v", titles(keys))
	}
	if _, ok := r.titled("JP-POS-002", "GCP"); !ok {
		t.Errorf("JP-POS-002 = %+v", titles(r.rule("JP-POS-002")))
	}
	if _, ok := r.titled("JP-POS-003", "GCP"); !ok {
		t.Errorf("JP-POS-003 = %+v", titles(r.rule("JP-POS-003")))
	}
	if _, ok := r.titled("JP-POS-004", "GCP"); !ok {
		t.Errorf("JP-POS-004 = %+v", titles(r.rule("JP-POS-004")))
	}
}

func titles(findings []finding.Finding) []string {
	out := make([]string, len(findings))
	for i, f := range findings {
		out[i] = f.Title
	}
	return out
}

func TestGCPControlsSatisfied(t *testing.T) {
	files := map[string]string{"infra/gcp.tf": `
resource "google_project_service" "vertex" {
  service = "aiplatform.googleapis.com"
}

resource "google_org_policy_policy" "restrict" {
  name   = "organizations/1/policies/gcp.restrictServiceUsage"
  parent = "organizations/1"
}

resource "google_project_iam_audit_config" "vertex" {
  project = "p"
  service = "aiplatform.googleapis.com"
  audit_log_config {
    log_type = "DATA_READ"
  }
  audit_log_config {
    log_type = "DATA_WRITE"
  }
}

resource "google_billing_budget" "all" {
  billing_account = "x"
}

resource "google_service_usage_consumer_quota_override" "vertex" {
  service = "aiplatform.googleapis.com"
  metric  = "m"
  limit   = "l"
}
`}
	r := runPosture(t, "", files)
	for _, id := range []string{"JP-POS-002", "JP-POS-003", "JP-POS-004", "JP-POS-005"} {
		if got := r.rule(id); len(got) != 0 {
			t.Errorf("%s = %+v", id, titles(got))
		}
	}
}

func TestAzure(t *testing.T) {
	files := map[string]string{"prod/azure.tf": `
resource "azurerm_cognitive_account" "openai" {
  name = "oai"
  kind = "OpenAI"
}

resource "azurerm_cognitive_deployment" "chat" {
  name                 = "chat"
  cognitive_account_id = azurerm_cognitive_account.openai.id
}

resource "azurerm_role_assignment" "owner" {
  scope                = "/subscriptions/0000"
  role_definition_name = "Owner"
  principal_id         = azurerm_user_assigned_identity.app.principal_id
}

resource "azurerm_role_assignment" "contributor" {
  scope                = "/subscriptions/0000"
  role_definition_name = "Cognitive Services Contributor"
  principal_id         = azurerm_user_assigned_identity.deploy.principal_id
}

resource "azurerm_role_assignment" "scoped_user" {
  scope                = "/subscriptions/0000/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/oai"
  role_definition_name = "Cognitive Services OpenAI User"
  principal_id         = azurerm_user_assigned_identity.app.principal_id
}
`}
	r := runPosture(t, environments, files)
	if _, ok := r.titled("JP-POS-001", "azurerm_user_assigned_identity.deploy can enable Azure OpenAI"); !ok {
		t.Errorf("JP-POS-001 = %+v", titles(r.rule("JP-POS-001")))
	}
	if broad := r.rule("JP-POS-006"); len(broad) != 2 || !strings.Contains(strings.Join(titles(broad), " "), "holds Owner") {
		t.Errorf("JP-POS-006 = %+v", titles(broad))
	}
	if _, ok := r.titled("JP-POS-003", "has no diagnostic setting"); !ok {
		t.Errorf("JP-POS-003 = %+v", titles(r.rule("JP-POS-003")))
	}
	if _, ok := r.titled("JP-POS-005", "set no capacity"); !ok {
		t.Errorf("JP-POS-005 = %+v", titles(r.rule("JP-POS-005")))
	}
	if _, ok := r.titled("JP-POS-002", "AZURE"); !ok {
		t.Errorf("JP-POS-002 = %+v", titles(r.rule("JP-POS-002")))
	}
	if _, ok := r.titled("JP-POS-004", "AZURE"); !ok {
		t.Errorf("JP-POS-004 = %+v", titles(r.rule("JP-POS-004")))
	}
}

func TestAzureControlsSatisfied(t *testing.T) {
	files := map[string]string{"infra/azure.tf": `
resource "azurerm_cognitive_account" "openai" {
  name = "oai"
  kind = "OpenAI"
}

resource "azurerm_cognitive_deployment" "chat" {
  name                 = "chat"
  cognitive_account_id = azurerm_cognitive_account.openai.id
  sku {
    name     = "Standard"
    capacity = 10
  }
}

resource "azurerm_monitor_diagnostic_setting" "openai" {
  name               = "audit"
  target_resource_id = azurerm_cognitive_account.openai.id
}

resource "azurerm_policy_definition" "deny_ai" {
  name        = "deny-ai"
  policy_type = "Custom"
  mode        = "All"
  policy_rule = <<-RULE
    {"if": {"field": "type", "equals": "Microsoft.CognitiveServices/accounts"}, "then": {"effect": "deny"}}
  RULE
}

resource "azurerm_consumption_budget_subscription" "all" {
  name = "all"
}
`}
	r := runPosture(t, "", files)
	for _, id := range []string{"JP-POS-002", "JP-POS-003", "JP-POS-004", "JP-POS-005"} {
		if got := r.rule(id); len(got) != 0 {
			t.Errorf("%s = %+v", id, titles(got))
		}
	}
}

func TestNotActionStatementsAreReportedInCoverage(t *testing.T) {
	files := map[string]string{"main.tf": `
resource "aws_iam_policy" "p" {
  policy = jsonencode({
    Statement = [{ Effect = "Allow", NotAction = ["iam:*"], Resource = "*" }]
  })
}
`}
	r := runPosture(t, "", files)
	found := false
	for _, skip := range r.infra.Coverage.FilesSkipped {
		if strings.Contains(skip.Reason, "NotAction") {
			found = true
		}
	}
	if !found {
		t.Errorf("coverage = %+v", r.infra.Coverage)
	}
}

func TestTerraformErrorsAreSkippedNotFatal(t *testing.T) {
	r := runPosture(t, "", map[string]string{"bad/main.tf": "resource \"a\" {", "good/main.tf": "variable \"x\" {}\n"})
	if len(r.infra.Coverage.FilesSkipped) != 1 || r.infra.Coverage.FilesSkipped[0].Path != "bad/main.tf" {
		t.Errorf("skips = %+v", r.infra.Coverage.FilesSkipped)
	}
	if r.infra.Coverage.FilesScanned["terraform"] != 1 {
		t.Errorf("scanned = %+v", r.infra.Coverage.FilesScanned)
	}
}

func TestAnalyzeRequiresPostureRules(t *testing.T) {
	cfg := config.Default()
	knowledge, err := LoadKnowledge()
	if err != nil {
		t.Fatal(err)
	}
	empty, err := rules.Load(emptyFS{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Analyze(newInfra(), nil, cfg, empty, knowledge); err == nil {
		t.Error("expected an error for a catalogue without the posture rules")
	}
}
