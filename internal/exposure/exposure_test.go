package exposure

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ryankshah/jackproof/internal/config"
	"github.com/ryankshah/jackproof/internal/finding"
	"github.com/ryankshah/jackproof/internal/rules"
	"github.com/ryankshah/jackproof/internal/scan"
	"github.com/ryankshah/jackproof/internal/secret"
)

var leakedKey = "sk-" + strings.Repeat("b", 48)

func composeFile() string {
	return "services:\n  api:\n    image: chat-api:1\n    env_file: .env\n  eval-runner:\n    image: eval-harness:1\n    environment:\n      OPENAI_API_KEY: ${OPENAI_API_KEY}\n"
}

func fixtureTree() map[string]string {
	return map[string]string{
		"jackproof.yaml":               "environments:\n  dev: [\"dev/**\"]\n  prod: [\"prod/**\"]\n",
		"dev/.env":                     "OPENAI_API_KEY=" + leakedKey + "\n",
		"dev/compose.yaml":             composeFile(),
		"prod/.env":                    "OPENAI_API_KEY=" + leakedKey + "\n",
		"prod/compose.yaml":            composeFile(),
		"Dockerfile":                   "FROM alpine\nENV OPENAI_API_KEY=" + leakedKey + "\n",
		".github/workflows/deploy.yml": "on: push\njobs:\n  deploy:\n    environment: prod\n    runs-on: ubuntu-latest\n    env:\n      OPENAI_API_KEY: ${{ secrets.OPENAI_PROD_KEY }}\n    steps:\n      - run: ./deploy.sh\n",
		"scripts/rotate.sh":            "gh secret set OPENAI_PROD_KEY --body \"$NEW\"\n",
		"scripts/other.sh":             "echo OPENAI_PROD_KEY_OLD\n",
	}
}

func scanFixture(t *testing.T) (*scan.Result, *rules.Catalogue, *secret.Catalogue) {
	t.Helper()
	root := t.TempDir()
	for name, content := range fixtureTree() {
		target := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := config.LoadIfPresent(root)
	if err != nil {
		t.Fatal(err)
	}
	ruleSet, err := rules.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	secrets, err := secret.LoadCatalogue()
	if err != nil {
		t.Fatal(err)
	}
	scanner, err := scan.New(cfg, ruleSet, secrets)
	if err != nil {
		t.Fatal(err)
	}
	result, err := scanner.Run([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	return result, ruleSet, secrets
}

func analyze(t *testing.T, targets []Target) *Analysis {
	t.Helper()
	result, ruleSet, secrets := scanFixture(t)
	analysis, err := Analyze(result, targets, ruleSet, secrets)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range analysis.Findings {
		if err := f.Validate(); err != nil {
			t.Errorf("finding %s is invalid: %v", f.ID, err)
		}
	}
	return analysis
}

func fingerprintTarget(algo, value string) Target {
	return Target{Kind: fingerprintKind, Algo: algo, Value: value, Source: Source{Path: "notice.txt", Line: 4}}
}

func TestFingerprintMatchFindsEveryLocation(t *testing.T) {
	digests := secret.Digests(leakedKey)
	tests := []struct {
		name   string
		target Target
	}{
		{"short sha256", fingerprintTarget("sha256", secret.Fingerprint(leakedKey))},
		{"full sha256", fingerprintTarget("sha256", digests["sha256"][:16])},
		{"sha1 provider fingerprint", fingerprintTarget("sha1", digests["sha1"])},
		{"sha512 prefix", fingerprintTarget("sha512", digests["sha512"][:32])},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analysis := analyze(t, []Target{tt.target})
			if len(analysis.Findings) != 1 || analysis.Findings[0].Rule != "JP-EXP-001" {
				t.Fatalf("findings = %+v", analysis.Findings)
			}
			f := analysis.Findings[0]
			if f.Confidence != finding.ConfidenceHigh || f.Method != finding.MethodFingerprintMatch {
				t.Errorf("confidence %s method %s", f.Confidence, f.Method)
			}
			exposure := analysis.Exposures[0]
			paths := make(map[string]string)
			for _, location := range exposure.Locations {
				paths[location.Path+":"+location.Role] = location.Excerpt
			}
			for _, want := range []string{"dev/.env:definition", "prod/.env:definition", "Dockerfile:definition", "dev/compose.yaml:injection", "prod/compose.yaml:injection"} {
				if _, ok := paths[want]; !ok {
					t.Errorf("missing location %s in %v", want, paths)
				}
			}
			for _, excerpt := range paths {
				if strings.Contains(excerpt, leakedKey) {
					t.Errorf("excerpt contains the full key: %s", excerpt)
				}
			}
			if exposure.Provider != "openai" || exposure.Reach == "" {
				t.Errorf("provider %q reach %q", exposure.Provider, exposure.Reach)
			}
			if exposure.Locations[0].Role != roleDefinition {
				t.Errorf("definitions must sort first, got %s", exposure.Locations[0].Role)
			}
		})
	}
}

func TestNameMatchUsesGraphAndTextReferences(t *testing.T) {
	analysis := analyze(t, []Target{{Kind: nameKind, Value: "OPENAI_PROD_KEY", Source: Source{Path: "names.txt", Line: 1}}})
	f := analysis.Findings[0]
	if f.Rule != "JP-EXP-001" || f.Confidence != finding.ConfidenceMedium || !hasFlag(f, finding.FlagInferred) {
		t.Fatalf("finding = %+v", f)
	}
	roles := make(map[string]string)
	for _, location := range analysis.Exposures[0].Locations {
		roles[location.Path] = location.Role
	}
	if roles[".github/workflows/deploy.yml"] != roleInjection {
		t.Errorf("workflow role = %q, locations = %v", roles[".github/workflows/deploy.yml"], roles)
	}
	if roles["scripts/rotate.sh"] != roleReference {
		t.Errorf("script role = %q", roles["scripts/rotate.sh"])
	}
	if _, found := roles["scripts/other.sh"]; found {
		t.Error("a longer name that merely starts with the target must not match")
	}
	if len(analysis.Exposures[0].Locations) != 2 {
		t.Errorf("locations = %+v", analysis.Exposures[0].Locations)
	}
}

func TestNotFoundIsReportedAsIncomplete(t *testing.T) {
	analysis := analyze(t, []Target{
		fingerprintTarget("sha256", "0123456789abcdef"),
		{Kind: nameKind, Value: "NO_SUCH_SECRET", Source: Source{Path: "names.txt", Line: 2}},
	})
	if len(analysis.Findings) != 2 {
		t.Fatalf("findings = %d", len(analysis.Findings))
	}
	for _, f := range analysis.Findings {
		if f.Rule != "JP-EXP-002" || !hasFlag(f, finding.FlagIncomplete) || len(f.Unproven) == 0 {
			t.Errorf("finding = %+v", f)
		}
		if f.Evidence[0].Path != "notice.txt" && f.Evidence[0].Path != "names.txt" {
			t.Errorf("evidence path = %s", f.Evidence[0].Path)
		}
	}
	for _, credential := range analysis.Plan.Credentials {
		if credential.Found {
			t.Error("plan marks an unmatched target as found")
		}
	}
}

func hasFlag(f finding.Finding, flag finding.Flag) bool {
	for _, candidate := range f.Flags {
		if candidate == flag {
			return true
		}
	}
	return false
}

func TestRotationPlan(t *testing.T) {
	analysis := analyze(t, []Target{
		fingerprintTarget("sha256", secret.Fingerprint(leakedKey)),
		{Kind: nameKind, Value: "OPENAI_PROD_KEY", Source: Source{Path: "names.txt", Line: 1}},
	})
	plan := analysis.Plan
	if len(plan.Credentials) != 2 {
		t.Fatalf("plan has %d credentials", len(plan.Credentials))
	}
	if plan.Credentials[0].Blast.Score <= plan.Credentials[1].Blast.Score {
		t.Errorf("plan is not ordered by blast radius: %+v", plan.Credentials)
	}
	if !strings.Contains(plan.Statement, "Deleting a stored secret does not revoke it") {
		t.Errorf("statement = %q", plan.Statement)
	}

	first := plan.Credentials[0]
	if len(first.Blast.Environments) != 2 || first.Blast.Untrusted != 2 {
		t.Errorf("blast = %+v", first.Blast)
	}
	phases := make([]string, len(first.Steps))
	for i, step := range first.Steps {
		phases[i] = step.Phase
		if step.Order != i+1 {
			t.Errorf("step %d has order %d", i, step.Order)
		}
	}
	want := []string{PhaseCreate, PhaseUpdate, PhaseRebuild, PhaseRestart, PhaseVerify, PhaseRevoke, PhaseCleanup}
	if strings.Join(phases, ",") != strings.Join(want, ",") {
		t.Errorf("phases = %v, want %v", phases, want)
	}
	if !strings.Contains(first.Steps[0].Action, "one replacement openai credential for each environment (dev, prod)") {
		t.Errorf("create action = %q", first.Steps[0].Action)
	}

	var restart Step
	for _, step := range first.Steps {
		if step.Phase == PhaseRestart {
			restart = step
		}
	}
	if len(restart.Targets) == 0 {
		t.Fatal("restart step has no targets")
	}
	seenProd := false
	for _, target := range restart.Targets {
		if strings.Contains(target.Detail, "(prod)") {
			seenProd = true
		} else if seenProd && strings.Contains(target.Detail, "(dev)") {
			t.Errorf("dev workload is restarted after prod: %+v", restart.Targets)
		}
	}
	if !seenProd {
		t.Error("prod workloads are missing from the restart order")
	}
	if !strings.Contains(first.Steps[len(first.Steps)-2].Action, "Deleting a stored secret does not revoke it") {
		t.Errorf("revoke action = %q", first.Steps[len(first.Steps)-2].Action)
	}

	var markdown bytes.Buffer
	if err := plan.WriteMarkdown(&markdown); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"### Fingerprint ", "Blast radius:", "2 that may run untrusted code", "1. **Create.**", "**Revoke.**", "`Dockerfile:2`"} {
		if !strings.Contains(markdown.String(), expected) {
			t.Errorf("markdown lacks %q:\n%s", expected, markdown.String())
		}
	}
}

func TestParseFingerprints(t *testing.T) {
	full := secret.FullFingerprint("abc")
	tests := []struct {
		name    string
		algo    string
		input   string
		want    int
		wantErr bool
	}{
		{"mixed forms", "sha256", "# notice\n\n" + full + "\nBA7816BF8F01CFEA\n", 2, false},
		{"bad length", "sha256", "abcd\n", 0, true},
		{"not hex", "sha256", "zz7816bf8f01cfea\n", 0, true},
		{"sha1 full", "sha1", secret.Digests("abc")["sha1"] + "\n", 1, false},
		{"sha1 too short", "sha1", "abcd\n", 0, true},
		{"unknown algorithm", "md5", "0123456789abcdef\n", 0, true},
		{"empty", "sha256", "", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			targets, err := ParseFingerprints(tt.algo, "notice.txt", []byte(tt.input))
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if len(targets) != tt.want {
				t.Errorf("got %d targets, want %d", len(targets), tt.want)
			}
		})
	}
}

func TestParseNamesAndKeys(t *testing.T) {
	names, err := ParseNames("names.txt", []byte("# header\nOPENAI_PROD_KEY\n\n  prod/anthropic  \n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 2 || names[1].Value != "prod/anthropic" || names[1].Source.Line != 4 {
		t.Errorf("names = %+v", names)
	}

	keys := TargetsFromKeys([]byte(leakedKey + "\n\n" + leakedKey + "x\n"))
	if len(keys) != 2 {
		t.Fatalf("keys = %+v", keys)
	}
	if keys[0].Value != secret.Fingerprint(leakedKey) || keys[0].Source.Path != "stdin" || keys[1].Source.Line != 3 {
		t.Errorf("keys = %+v", keys)
	}
	for _, key := range keys {
		if strings.Contains(key.Label(), leakedKey) || strings.Contains(key.Value, leakedKey) {
			t.Error("a target contains the raw key")
		}
	}
}

func TestAnalyzeRequiresRules(t *testing.T) {
	result, _, secrets := scanFixture(t)
	empty, err := rules.Load(emptyFS{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Analyze(result, nil, empty, secrets); err == nil {
		t.Error("expected an error for a catalogue without the exposure rules")
	}
}

func TestSecretManagerNamesMatchCodeAndArns(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"svc/app.py":   "import boto3\nkey = boto3.client('secretsmanager').get_secret_value(SecretId='prod/openai-key')\n",
		"infra/ecs.tf": "resource \"aws_ecs_task_definition\" \"chat\" {\n  family = \"chat\"\n  container_definitions = jsonencode([{\n    name = \"api\"\n    image = \"chat:1\"\n    secrets = [{ name = \"ANTHROPIC_API_KEY\", valueFrom = \"arn:aws:secretsmanager:us-east-1:111122223333:secret:prod/anthropic-AbCdEf\" }]\n  }])\n}\n",
	}
	for name, content := range files {
		target := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg, _ := config.LoadIfPresent(root)
	ruleSet, _ := rules.LoadEmbedded()
	secrets, _ := secret.LoadCatalogue()
	scanner, err := scan.New(cfg, ruleSet, secrets)
	if err != nil {
		t.Fatal(err)
	}
	result, err := scanner.Run([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		value    string
		wantPath string
		wantRole string
	}{
		{"code lookup by name", "prod/openai-key", "svc/app.py", roleInjection},
		{"arn matched by plain name", "prod/anthropic", "infra/ecs.tf", roleInjection},
		{"arn matched with its random suffix", "prod/anthropic-AbCdEf", "infra/ecs.tf", roleInjection},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analysis, err := Analyze(result, []Target{{Kind: nameKind, Value: tt.value, Source: Source{Path: "names.txt", Line: 1}}}, ruleSet, secrets)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, location := range analysis.Exposures[0].Locations {
				if location.Path == tt.wantPath && location.Role == tt.wantRole {
					found = true
				}
			}
			if !found {
				t.Errorf("locations = %+v", analysis.Exposures[0].Locations)
			}
		})
	}
	partial, err := Analyze(result, []Target{{Kind: nameKind, Value: "prod", Source: Source{Path: "names.txt", Line: 1}}}, ruleSet, secrets)
	if err != nil {
		t.Fatal(err)
	}
	for _, location := range partial.Exposures[0].Locations {
		if location.Role == roleInjection {
			t.Errorf("a path prefix must not match a secret: %+v", location)
		}
	}
}

func TestReferenceNames(t *testing.T) {
	tests := []struct {
		identity string
		want     []string
	}{
		{"env:OPENAI_API_KEY", []string{"OPENAI_API_KEY"}},
		{"gha-secret:OPENAI_PROD_KEY", []string{"OPENAI_PROD_KEY"}},
		{"k8s-secret:llm-keys/openai", []string{"llm-keys/openai", "llm-keys", "openai"}},
		{"aws-secret:prod/openai-key", []string{"prod/openai-key"}},
		{"aws-secret:arn:aws:secretsmanager:us-east-1:1:secret:prod/x-AbCdEf", []string{"arn:aws:secretsmanager:us-east-1:1:secret:prod/x-AbCdEf", "prod/x-AbCdEf", "prod/x"}},
		{"plain", []string{"plain"}},
	}
	for _, tt := range tests {
		t.Run(tt.identity, func(t *testing.T) {
			if got := referenceNames(tt.identity); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}
