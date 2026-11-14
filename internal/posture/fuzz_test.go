package posture

import (
	"testing"

	"github.com/ryankshah/jackproof/internal/config"
	"github.com/ryankshah/jackproof/internal/rules"
)

func FuzzPosture(f *testing.F) {
	f.Add([]byte(enablerPolicy("deployer")))
	f.Add([]byte("resource \"google_project_iam_member\" \"m\" {\n  role = \"roles/owner\"\n  member = \"serviceAccount:${google_service_account.a.email}\"\n}\n"))
	f.Add([]byte("resource \"azurerm_role_assignment\" \"r\" {\n  scope = \"/subscriptions/x\"\n  role_definition_name = \"Owner\"\n  principal_id = azurerm_user_assigned_identity.a.principal_id\n}\n"))
	f.Add([]byte("resource \"aws_iam_policy\" \"p\" {\n  policy = jsonencode({Statement = [{Effect = \"Allow\", NotAction = [\"iam:*\"], Resource = \"*\"}]})\n}\n"))
	f.Add([]byte("resource \"a\" {"))
	knowledge, err := LoadKnowledge()
	if err != nil {
		f.Fatal(err)
	}
	ruleSet, err := rules.LoadEmbedded()
	if err != nil {
		f.Fatal(err)
	}
	cfg := config.Default()
	f.Fuzz(func(t *testing.T, data []byte) {
		sources := []Source{{Path: "fuzz/main.tf", Data: data}}
		infra := Extract(sources, cfg, knowledge)
		findings, err := Analyze(infra, sources, cfg, ruleSet, knowledge)
		if err != nil {
			t.Fatal(err)
		}
		for _, finding := range findings {
			if err := finding.Validate(); err != nil {
				t.Fatalf("invalid finding: %v", err)
			}
		}
	})
}
