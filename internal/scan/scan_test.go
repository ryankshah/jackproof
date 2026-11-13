package scan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ryankshah/jackproof/internal/config"
	"github.com/ryankshah/jackproof/internal/finding"
	"github.com/ryankshah/jackproof/internal/graph"
	"github.com/ryankshah/jackproof/internal/rules"
	"github.com/ryankshah/jackproof/internal/secret"
)

var (
	anthropicKey = "sk-" + "ant-" + strings.Repeat("x", 90)
	openaiKey    = "sk-" + strings.Repeat("b", 48)
	awsKeyID     = "AK" + "IA" + strings.Repeat("A", 16)
)

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		target := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func newScanner(t *testing.T, configYAML string) *Scanner {
	t.Helper()
	cfg, err := config.Parse([]byte(configYAML))
	if err != nil {
		t.Fatal(err)
	}
	return newScannerWithConfig(t, cfg, nil)
}

func newScannerWithConfig(t *testing.T, cfg *config.Config, extra *rules.Catalogue) *Scanner {
	t.Helper()
	ruleSet, err := rules.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	if extra != nil {
		if ruleSet, err = ruleSet.Merge(extra); err != nil {
			t.Fatal(err)
		}
	}
	secrets, err := secret.LoadCatalogue()
	if err != nil {
		t.Fatal(err)
	}
	scanner, err := New(cfg, ruleSet, secrets)
	if err != nil {
		t.Fatal(err)
	}
	return scanner
}

func runScan(t *testing.T, configYAML string, files map[string]string) *Result {
	t.Helper()
	result, err := newScanner(t, configYAML).Run([]string{writeTree(t, files)})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range result.Findings {
		if err := f.Validate(); err != nil {
			t.Errorf("finding %s (%s) is invalid: %v", f.ID, f.Rule, err)
		}
		for _, evidence := range f.Evidence {
			for _, secretValue := range []string{anthropicKey, openaiKey, awsKeyID} {
				if strings.Contains(evidence.Excerpt, secretValue) || strings.Contains(f.Title, secretValue) {
					t.Errorf("finding %s leaks a full secret", f.ID)
				}
			}
		}
	}
	return result
}

func findingsFor(result *Result, rule string) []finding.Finding {
	var matched []finding.Finding
	for _, f := range result.Findings {
		if f.Rule == rule {
			matched = append(matched, f)
		}
	}
	return matched
}

func findingAt(result *Result, rule, path string) (finding.Finding, bool) {
	for _, f := range findingsFor(result, rule) {
		if f.Evidence[0].Path == path {
			return f, true
		}
	}
	return finding.Finding{}, false
}

func TestLiteralKeys(t *testing.T) {
	result := runScan(t, "", map[string]string{
		".env":          "ANTHROPIC_API_KEY=" + anthropicKey + "\nOPENAI_API_KEY=${OPENAI_API_KEY}\n",
		".env.example":  "OPENAI_API_KEY=" + openaiKey + "\n",
		"app/client.py": "client = Anthropic(api_key=\"" + anthropicKey + "\")\n",
		"notes.txt":     "no secrets here\n",
	})
	literals := findingsFor(result, "JP-KEY-001")
	if len(literals) != 3 {
		t.Fatalf("got %d JP-KEY-001 findings, want 3: %+v", len(literals), literals)
	}
	wantConfidence := map[string]finding.Confidence{
		".env":          finding.ConfidenceHigh,
		".env.example":  finding.ConfidenceLow,
		"app/client.py": finding.ConfidenceHigh,
	}
	for _, f := range literals {
		path := f.Evidence[0].Path
		if f.Confidence != wantConfidence[path] {
			t.Errorf("%s confidence = %s, want %s", path, f.Confidence, wantConfidence[path])
		}
		if !containsFlag(f.Flags, finding.FlagUnverifiedRule) {
			t.Errorf("%s lacks the unverified-rule flag", path)
		}
		if f.Evidence[0].StartLine != 1 {
			t.Errorf("%s line = %d, want 1", path, f.Evidence[0].StartLine)
		}
	}
	credentials := result.Graph.Credentials()
	literalCount := 0
	for _, credential := range credentials {
		if credential.Kind == graph.KindLiteral {
			literalCount++
			if len(credential.Redacted) == 0 || strings.Contains(credential.Redacted, strings.Repeat("x", 20)) {
				t.Errorf("credential redaction looks wrong: %q", credential.Redacted)
			}
		}
	}
	if literalCount != 2 {
		t.Errorf("literal credentials = %d, want 2 (one per distinct key)", literalCount)
	}
}

func TestCleanRepositoryHasCoverageButNoFindings(t *testing.T) {
	result := runScan(t, "", map[string]string{
		"main.go":    "package main\n\nfunc main() {}\n",
		"README.md":  "A readme.\n",
		"config.yml": "retries: 3\n",
	})
	if len(result.Findings) != 0 {
		t.Errorf("unexpected findings: %+v", result.Findings)
	}
	if result.Coverage.TotalScanned() != 3 {
		t.Errorf("scanned = %d, want 3", result.Coverage.TotalScanned())
	}
	if len(result.Coverage.UnverifiedRules) == 0 {
		t.Error("coverage should list unverified rules and formats")
	}
}

func TestCoverageRecordsSkips(t *testing.T) {
	files := map[string]string{
		"main.go":                 "package main\n",
		"node_modules/dep/a.js":   "x\n",
		"vendor/lib/b.go":         "package lib\n",
		"blob.bin":                "a\x00b",
		"big.txt":                 strings.Repeat("a", maxFileSize+1),
		"generated/skipped.txt":   "x\n",
		"generated/also/keep.txt": "x\n",
	}
	result := runScan(t, "ignore:\n  paths:\n    - \"generated/**\"\n", files)
	reasons := make(map[string]string)
	for _, skip := range result.Coverage.FilesSkipped {
		reasons[skip.Path] = skip.Reason
	}
	want := map[string]string{
		"node_modules/": "third-party dependencies",
		"vendor/":       "third-party dependencies",
		"blob.bin":      "binary file",
		"generated/":    "ignored by configuration",
		"big.txt":       "larger than",
	}
	for path, reason := range want {
		if !strings.Contains(reasons[path], reason) {
			t.Errorf("skip reason for %s = %q, want it to contain %q", path, reasons[path], reason)
		}
	}
	if result.Coverage.FilesScanned["go"] != 1 {
		t.Errorf("scanned go files = %d, want 1", result.Coverage.FilesScanned["go"])
	}
}

func TestComposeEnvironmentsAndUntrustedRunner(t *testing.T) {
	compose := func(extra string) string {
		return "services:\n  api:\n    image: nginx:1\n    environment:\n      OPENAI_API_KEY: ${OPENAI_API_KEY}\n" + extra
	}
	result := runScan(t, "environments:\n  dev: [\"dev/**\"]\n  prod: [\"prod/**\"]\n", map[string]string{
		"dev/.env":             "OPENAI_API_KEY=" + openaiKey + "\n",
		"dev/compose.yaml":     compose("  eval-runner:\n    image: runner:1\n    env_file: .env\n"),
		"prod/.env":            "OPENAI_API_KEY=" + openaiKey + "\n",
		"prod/compose.yaml":    compose(""),
		"staging/compose.yaml": "services:\n  api:\n    environment:\n      LOG_LEVEL: debug\n",
	})

	shared := findingsFor(result, "JP-KEY-010")
	if len(shared) != 1 {
		t.Fatalf("got %d JP-KEY-010 findings, want 1: %+v", len(shared), shared)
	}
	if shared[0].Confidence != finding.ConfidenceHigh || len(shared[0].Evidence) != 2 {
		t.Errorf("shared finding = confidence %s, evidence %d", shared[0].Confidence, len(shared[0].Evidence))
	}
	if !strings.Contains(shared[0].Title, "dev and prod") {
		t.Errorf("title = %q", shared[0].Title)
	}

	untrusted := findingsFor(result, "JP-KEY-020")
	if len(untrusted) != 1 {
		t.Fatalf("got %d JP-KEY-020 findings, want 1: %+v", len(untrusted), untrusted)
	}
	if untrusted[0].Confidence != finding.ConfidenceMedium || !containsFlag(untrusted[0].Flags, finding.FlagInferred) {
		t.Errorf("untrusted finding = %+v", untrusted[0])
	}
	if untrusted[0].Evidence[0].Path != "dev/compose.yaml" {
		t.Errorf("evidence path = %s", untrusted[0].Evidence[0].Path)
	}
	if len(untrusted[0].Unproven) == 0 {
		t.Error("an inferred finding must say what is unproven")
	}
}

func TestInterpolationFromExampleFileIsInferred(t *testing.T) {
	result := runScan(t, "", map[string]string{
		".env.example": "OPENAI_API_KEY=" + openaiKey + "\n",
		"compose.yaml": "services:\n  eval-runner:\n    environment:\n      OPENAI_API_KEY: ${OPENAI_API_KEY}\n",
	})
	edges := result.Graph.Edges()
	if len(edges) != 1 {
		t.Fatalf("edges = %+v", edges)
	}
	if !edges[0].Inferred || !strings.HasPrefix(edges[0].Credential, "literal:") {
		t.Errorf("edge = %+v", edges[0])
	}
}

func TestKubernetes(t *testing.T) {
	manifest := func(namespace, name string) string {
		return "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: " + name + "\n  namespace: " + namespace + "\nspec:\n  template:\n    spec:\n      containers:\n        - name: app\n          image: app:1\n          env:\n            - name: OPENAI_API_KEY\n              valueFrom:\n                secretKeyRef:\n                  name: llm-keys\n                  key: openai\n            - name: SENTRY_DSN\n              value: https://example.invalid/1\n"
	}
	result := runScan(t, "environments:\n  dev: [\"k8s/dev/**\"]\n  prod: [\"k8s/prod/**\"]\n", map[string]string{
		"k8s/dev/app.yaml":  manifest("dev", "chat"),
		"k8s/prod/app.yaml": manifest("prod", "chat"),
	})
	shared := findingsFor(result, "JP-KEY-010")
	if len(shared) != 1 || shared[0].Confidence != finding.ConfidenceMedium {
		t.Fatalf("JP-KEY-010 = %+v", shared)
	}
	if len(shared[0].Unproven) == 0 {
		t.Error("a reference-based finding must say what is unproven")
	}
	sinks := findingsFor(result, "JP-KEY-021")
	if len(sinks) != 2 {
		t.Errorf("got %d JP-KEY-021 findings, want 2: %+v", len(sinks), sinks)
	}
	for _, f := range sinks {
		if f.Confidence != finding.ConfidenceMedium || len(f.Evidence) != 2 {
			t.Errorf("sink finding = %+v", f)
		}
	}
}

func TestGitHubActions(t *testing.T) {
	workflow := func(trigger, checkoutRef string) string {
		checkout := "      - uses: actions/checkout@v4\n"
		if checkoutRef != "" {
			checkout += "        with:\n          ref: " + checkoutRef + "\n"
		}
		return "on: " + trigger + "\njobs:\n  review:\n    runs-on: ubuntu-latest\n    env:\n      OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}\n    steps:\n" + checkout +
			"      - uses: aws-actions/configure-aws-credentials@v4\n        with:\n          aws-access-key-id: ${{ secrets.CI_AWS_ID }}\n          aws-secret-access-key: ${{ secrets.CI_AWS_SECRET }}\n" +
			"      - run: |\n          make test\n          printenv\n"
	}
	tests := []struct {
		name           string
		trigger        string
		checkoutRef    string
		wantUntrusted  int
		wantConfidence finding.Confidence
	}{
		{"pull_request_target with PR checkout", "pull_request_target", "${{ github.event.pull_request.head.sha }}", 3, finding.ConfidenceHigh},
		{"pull_request_target without PR checkout", "pull_request_target", "", 3, finding.ConfidenceMedium},
		{"push", "push", "", 0, ""},
		{"pull_request", "pull_request", "${{ github.event.pull_request.head.sha }}", 0, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := runScan(t, "", map[string]string{".github/workflows/review.yml": workflow(tt.trigger, tt.checkoutRef)})
			untrusted := findingsFor(result, "JP-KEY-020")
			if len(untrusted) != tt.wantUntrusted {
				t.Fatalf("JP-KEY-020 count = %d, want %d", len(untrusted), tt.wantUntrusted)
			}
			for _, f := range untrusted {
				if f.Confidence != tt.wantConfidence {
					t.Errorf("%s confidence = %s, want %s", f.Title, f.Confidence, tt.wantConfidence)
				}
			}
			if got := len(findingsFor(result, "JP-KEY-021")); got != 1 {
				t.Errorf("JP-KEY-021 count = %d, want 1", got)
			}
			static := findingsFor(result, "JP-KEY-030")
			if len(static) != 1 || static[0].Confidence != finding.ConfidenceHigh {
				t.Errorf("JP-KEY-030 = %+v", static)
			}
		})
	}
}

func TestDockerfile(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  map[finding.Confidence]int
	}{
		{
			name:  "literal ENV",
			files: map[string]string{"Dockerfile": "FROM x\nENV OPENAI_API_KEY=" + openaiKey + "\n"},
			want:  map[finding.Confidence]int{finding.ConfidenceHigh: 1},
		},
		{
			name:  "ENV from ARG",
			files: map[string]string{"Dockerfile": "FROM x\nARG OPENAI_API_KEY\nENV OPENAI_API_KEY=$OPENAI_API_KEY\n"},
			want:  map[finding.Confidence]int{finding.ConfidenceHigh: 1, finding.ConfidenceMedium: 1},
		},
		{
			name:  "empty ENV",
			files: map[string]string{"Dockerfile": "FROM x\nENV OPENAI_API_KEY=\n"},
			want:  map[finding.Confidence]int{},
		},
		{
			name:  "unrelated ENV",
			files: map[string]string{"Dockerfile": "FROM x\nENV LOG_LEVEL=debug\n"},
			want:  map[finding.Confidence]int{},
		},
		{
			name:  "copy dotenv",
			files: map[string]string{"Dockerfile": "FROM x\nCOPY .env /app/.env\n"},
			want:  map[finding.Confidence]int{finding.ConfidenceHigh: 1},
		},
		{
			name:  "copy example dotenv",
			files: map[string]string{"Dockerfile": "FROM x\nCOPY .env.example /app/\n"},
			want:  map[finding.Confidence]int{},
		},
		{
			name:  "copy context with dotenv present",
			files: map[string]string{"Dockerfile": "FROM x\nCOPY . /app\n", ".env": "LOG_LEVEL=debug\n"},
			want:  map[finding.Confidence]int{finding.ConfidenceMedium: 1},
		},
		{
			name:  "copy context with dotenv ignored",
			files: map[string]string{"Dockerfile": "FROM x\nCOPY . /app\n", ".env": "LOG_LEVEL=debug\n", ".dockerignore": "node_modules\n.env*\n"},
			want:  map[finding.Confidence]int{},
		},
		{
			name:  "copy context without dotenv",
			files: map[string]string{"Dockerfile": "FROM x\nCOPY . /app\n"},
			want:  map[finding.Confidence]int{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := runScan(t, "", tt.files)
			got := make(map[finding.Confidence]int)
			for _, f := range findingsFor(result, "JP-KEY-050") {
				got[f.Confidence]++
			}
			for confidence, count := range tt.want {
				if got[confidence] != count {
					t.Errorf("%s findings = %d, want %d (all: %v)", confidence, got[confidence], count, got)
				}
			}
			total := 0
			for _, count := range got {
				total += count
			}
			wantTotal := 0
			for _, count := range tt.want {
				wantTotal += count
			}
			if total != wantTotal {
				t.Errorf("total JP-KEY-050 findings = %d, want %d", total, wantTotal)
			}
		})
	}
}

func TestCodeLeaksAndNotebooks(t *testing.T) {
	notebook := "{\n \"cells\": [\n  {\n   \"cell_type\": \"code\",\n   \"source\": [\n    \"import os\\n\",\n    \"key = os.environ[\\\"OPENAI_API_KEY\\\"]\\n\",\n    \"print(key)\"\n   ]\n  }\n ]\n}\n"
	goSource := "package main\n\nimport (\n\t\"log\"\n\t\"os\"\n)\n\nfunc main() {\n\tkey := os.Getenv(\"OPENAI_API_KEY\")\n\tlog.Printf(\"key=%s\", key)\n}\n"
	pySource := "import os\nkey = os.environ[\"ANTHROPIC_API_KEY\"]\nprint(key)\n"
	result := runScan(t, "", map[string]string{
		"cmd/main.go":       goSource,
		"tools/run.py":      pySource,
		"lab/explore.ipynb": notebook,
	})

	leaks := findingsFor(result, "JP-KEY-040")
	if len(leaks) != 3 {
		t.Fatalf("got %d JP-KEY-040 findings, want 3: %+v", len(leaks), leaks)
	}
	want := map[string]struct {
		line       int
		confidence finding.Confidence
		method     finding.Method
	}{
		"cmd/main.go":       {10, finding.ConfidenceHigh, finding.MethodAST},
		"tools/run.py":      {3, finding.ConfidenceMedium, finding.MethodPattern},
		"lab/explore.ipynb": {8, finding.ConfidenceMedium, finding.MethodPattern},
	}
	for _, f := range leaks {
		expected := want[f.Evidence[0].Path]
		if f.Evidence[0].StartLine != expected.line || f.Confidence != expected.confidence || f.Method != expected.method {
			t.Errorf("%s: line %d confidence %s method %s, want %+v", f.Evidence[0].Path, f.Evidence[0].StartLine, f.Confidence, f.Method, expected)
		}
	}

	untrusted := findingsFor(result, "JP-KEY-020")
	if len(untrusted) != 1 || untrusted[0].Evidence[0].Path != "lab/explore.ipynb" {
		t.Fatalf("JP-KEY-020 = %+v", untrusted)
	}
	if untrusted[0].Evidence[0].StartLine != 7 {
		t.Errorf("notebook env read line = %d, want 7", untrusted[0].Evidence[0].StartLine)
	}
}

func TestIgnoredRulesAreDropped(t *testing.T) {
	files := map[string]string{".env": "ANTHROPIC_API_KEY=" + anthropicKey + "\n"}
	if got := len(findingsFor(runScan(t, "", files), "JP-KEY-001")); got != 1 {
		t.Fatalf("baseline JP-KEY-001 count = %d, want 1", got)
	}
	if got := len(findingsFor(runScan(t, "ignore:\n  rules: [JP-KEY-001]\n", files), "JP-KEY-001")); got != 0 {
		t.Errorf("ignored rule still reported %d findings", got)
	}
}

func TestCustomPatternRule(t *testing.T) {
	custom, err := rules.Load(mapFS(map[string]string{"JP-KEY-900.yaml": `id: JP-KEY-900
title: Internal gateway token
severity: high
verified: true
pattern: 'gw_[a-z0-9]{16}'
description: A token for the internal model gateway.
remediation: Rotate the token.
refs:
  - https://example.com/gateway
`}))
	if err != nil {
		t.Fatal(err)
	}
	scanner := newScannerWithConfig(t, config.Default(), custom)
	token := "gw" + "_" + strings.Repeat("a", 16)
	result, err := scanner.Run([]string{writeTree(t, map[string]string{"cfg.txt": "token=" + token + "\n", "other.txt": "nothing\n"})})
	if err != nil {
		t.Fatal(err)
	}
	matches := findingsFor(result, "JP-KEY-900")
	if len(matches) != 1 {
		t.Fatalf("got %d custom findings: %+v", len(matches), matches)
	}
	if strings.Contains(matches[0].Evidence[0].Excerpt, token) {
		t.Error("custom rule excerpt contains the full token")
	}
	if err := matches[0].Validate(); err != nil {
		t.Error(err)
	}
}

func TestNewRequiresCoreRules(t *testing.T) {
	empty, err := rules.Load(mapFS(nil))
	if err != nil {
		t.Fatal(err)
	}
	secrets, err := secret.LoadCatalogue()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(config.Default(), empty, secrets); err == nil {
		t.Error("expected an error for a catalogue without the core rules")
	}
}

func TestRunErrors(t *testing.T) {
	scanner := newScanner(t, "")
	tests := []struct {
		name  string
		roots []string
	}{
		{"no roots", nil},
		{"missing path", []string{filepath.Join(t.TempDir(), "absent")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := scanner.Run(tt.roots); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

func TestSingleFileRoot(t *testing.T) {
	root := writeTree(t, map[string]string{"only.env": "ANTHROPIC_API_KEY=" + anthropicKey + "\n"})
	result, err := newScanner(t, "").Run([]string{filepath.Join(root, "only.env")})
	if err != nil {
		t.Fatal(err)
	}
	if f, ok := findingAt(result, "JP-KEY-001", "only.env"); !ok || f.Evidence[0].StartLine != 1 {
		t.Errorf("findings = %+v", result.Findings)
	}
}

func TestUnparseableStructureIsReported(t *testing.T) {
	result := runScan(t, "", map[string]string{"compose.yaml": "services: [unclosed\n"})
	found := false
	for _, skip := range result.Coverage.FilesSkipped {
		if skip.Path == "compose.yaml" && strings.Contains(skip.Reason, "structure not analysed") {
			found = true
		}
	}
	if !found {
		t.Errorf("skips = %+v", result.Coverage.FilesSkipped)
	}
}
