package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ryankshah/jackproof/internal/posture"
	"github.com/ryankshah/jackproof/internal/rules"
	"github.com/ryankshah/jackproof/internal/scan/lang"
	"github.com/ryankshah/jackproof/internal/secret"
)

func renderAll(t *testing.T) (string, string) {
	t.Helper()
	catalogue, err := rules.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	providers, err := secret.LoadCatalogue()
	if err != nil {
		t.Fatal(err)
	}
	extractor, err := lang.New(func(string) bool { return false })
	if err != nil {
		t.Fatal(err)
	}
	knowledge, err := posture.LoadKnowledge()
	if err != nil {
		t.Fatal(err)
	}
	return renderRules(catalogue), renderUnverified(catalogue, providers, extractor, knowledge)
}

func TestCommittedDocumentsAreCurrent(t *testing.T) {
	rendered, unverified := renderAll(t)
	for name, want := range map[string]string{"rules.md": rendered, "unverified.md": unverified} {
		got, err := os.ReadFile(filepath.Join("..", "..", "docs", name))
		if err != nil {
			t.Fatalf("%s: %v. Run go generate ./...", name, err)
		}
		if strings.ReplaceAll(string(got), "\r\n", "\n") != want {
			t.Errorf("docs/%s is out of date. Run go generate ./...", name)
		}
	}
}

func TestRulesDocumentListsEveryRule(t *testing.T) {
	rendered, _ := renderAll(t)
	catalogue, err := rules.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range catalogue.All() {
		if !strings.Contains(rendered, "## "+rule.ID+"\n") || !strings.Contains(rendered, "| ["+rule.ID+"]") {
			t.Errorf("rules.md lacks %s", rule.ID)
		}
	}
}

func TestUnverifiedDocumentContent(t *testing.T) {
	_, unverified := renderAll(t)
	for _, want := range []string{"## Rules", "JP-KEY-001", "## Provider key formats", "anthropic, format api-key", "## Live verification endpoints", "api.openai.com", "## SDK client patterns", "python code, provider anthropic", "## Secret store lookup patterns", "aws-secret lookups", "## Cloud permissions and roles", "## Log event and field names", "InvokeModel", "## Heuristics"} {
		if !strings.Contains(unverified, want) {
			t.Errorf("unverified.md lacks %q", want)
		}
	}
	if strings.Contains(unverified, "aws, format access-key-id") {
		t.Error("a verified format is listed as unverified")
	}
}

func TestGenerateWritesBothFiles(t *testing.T) {
	directory := t.TempDir()
	if err := generate(directory); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"rules.md", "unverified.md"} {
		if info, err := os.Stat(filepath.Join(directory, name)); err != nil || info.Size() == 0 {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := generate(filepath.Join(directory, "missing")); err == nil {
		t.Error("expected an error for a directory that does not exist")
	}
}
