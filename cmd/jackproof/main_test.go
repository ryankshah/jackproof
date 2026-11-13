package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var testKey = "sk-" + "ant-" + strings.Repeat("x", 90)

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

func runCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	return runCLIWithInput(t, "", args...)
}

func runCLIWithInput(t *testing.T, input string, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(args, strings.NewReader(input), &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestRunBasics(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{"no arguments", nil, exitUsage, "", "usage: jackproof <command>"},
		{"version", []string{"version"}, exitOK, "dev\n", ""},
		{"help", []string{"help"}, exitOK, "commands:", ""},
		{"unknown command", []string{"nope"}, exitUsage, "", `unknown command "nope"`},
		{"scan help", []string{"scan", "-h"}, exitOK, "-fail-on", ""},
		{"scan bad flag", []string{"scan", "--bogus"}, exitUsage, "", "scan:"},
		{"scan bad format", []string{"scan", "--format", "pdf", t.TempDir()}, exitUsage, "", `unknown format "pdf"`},
		{"scan bad fail-on", []string{"scan", "--fail-on", "urgent", t.TempDir()}, exitUsage, "", "--fail-on"},
		{"scan bad min-confidence", []string{"scan", "--min-confidence", "sure", t.TempDir()}, exitUsage, "", "--min-confidence"},
		{"scan missing path", []string{"scan", filepath.Join(t.TempDir(), "absent")}, exitUsage, "", "scan:"},
		{"rules without subcommand", []string{"rules"}, exitUsage, "", "rules needs a subcommand"},
		{"rules unknown subcommand", []string{"rules", "remove"}, exitUsage, "", "unknown rules subcommand"},
		{"rules show without id", []string{"rules", "show"}, exitUsage, "", "needs one rule id"},
		{"rules show unknown", []string{"rules", "show", "JP-KEY-999"}, exitUsage, "", "no rule with id"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, stdout, stderr := runCLI(t, tt.args...)
			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d (stderr: %s)", code, tt.wantCode, stderr)
			}
			if !strings.Contains(stdout, tt.wantStdout) {
				t.Errorf("stdout = %q, want it to contain %q", stdout, tt.wantStdout)
			}
			if !strings.Contains(stderr, tt.wantStderr) {
				t.Errorf("stderr = %q, want it to contain %q", stderr, tt.wantStderr)
			}
		})
	}
}

func TestScanExitCodesAndFlags(t *testing.T) {
	leaky := writeTree(t, map[string]string{".env": "ANTHROPIC_API_KEY=" + testKey + "\n"})
	clean := writeTree(t, map[string]string{"main.go": "package main\n"})
	exampleOnly := writeTree(t, map[string]string{".env.example": "ANTHROPIC_API_KEY=" + testKey + "\n"})

	tests := []struct {
		name     string
		args     []string
		wantCode int
		want     string
		notWant  string
	}{
		{"findings fail by default", []string{"scan", leaky}, exitFindings, "JP-KEY-001", testKey},
		{"clean passes", []string{"scan", clean}, exitOK, "No findings", ""},
		{"fail-on critical passes", []string{"scan", "--fail-on", "critical", leaky}, exitOK, "JP-KEY-001", ""},
		{"flags after path", []string{"scan", leaky, "--fail-on", "critical"}, exitOK, "JP-KEY-001", ""},
		{"low confidence shown", []string{"scan", "--fail-on", "critical", exampleOnly}, exitOK, "JP-KEY-001", ""},
		{"min-confidence hides low", []string{"scan", "--min-confidence", "medium", exampleOnly}, exitOK, "No findings", "JP-KEY-001  "},
		{"markdown", []string{"scan", "--format", "md", "--fail-on", "critical", leaky}, exitOK, "### HIGH JP-KEY-001", testKey},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, stdout, stderr := runCLI(t, tt.args...)
			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d (stderr: %s)", code, tt.wantCode, stderr)
			}
			if !strings.Contains(stdout, tt.want) {
				t.Errorf("stdout lacks %q:\n%s", tt.want, stdout)
			}
			if tt.notWant != "" && strings.Contains(stdout, tt.notWant) {
				t.Errorf("stdout contains %q", tt.notWant)
			}
		})
	}
}

func TestScanStructuredFormats(t *testing.T) {
	leaky := writeTree(t, map[string]string{".env": "ANTHROPIC_API_KEY=" + testKey + "\n"})
	for _, format := range []string{"json", "sarif"} {
		t.Run(format, func(t *testing.T) {
			code, stdout, stderr := runCLI(t, "scan", "--format", format, "--fail-on", "critical", leaky)
			if code != exitOK {
				t.Fatalf("exit code = %d (stderr: %s)", code, stderr)
			}
			var decoded map[string]any
			if err := json.Unmarshal([]byte(stdout), &decoded); err != nil {
				t.Fatalf("output is not json: %v", err)
			}
			if strings.Contains(stdout, testKey) {
				t.Error("structured output contains the full key")
			}
		})
	}
}

func TestConfigFileIsUsed(t *testing.T) {
	root := writeTree(t, map[string]string{
		".env":           "ANTHROPIC_API_KEY=" + testKey + "\n",
		"jackproof.yaml": "ignore:\n  rules: [JP-KEY-001]\n",
	})
	code, stdout, stderr := runCLI(t, "scan", root)
	if code != exitOK || !strings.Contains(stdout, "No findings") {
		t.Errorf("code = %d, stdout = %s, stderr = %s", code, stdout, stderr)
	}

	other := writeTree(t, map[string]string{".env": "ANTHROPIC_API_KEY=" + testKey + "\n"})
	explicit := filepath.Join(root, "jackproof.yaml")
	code, stdout, _ = runCLI(t, "scan", "--config", explicit, other)
	if code != exitOK || !strings.Contains(stdout, "No findings") {
		t.Errorf("explicit config: code = %d, stdout = %s", code, stdout)
	}

	code, _, stderr = runCLI(t, "scan", "--config", filepath.Join(root, "absent.yaml"), other)
	if code != exitUsage || !strings.Contains(stderr, "read config") {
		t.Errorf("missing config: code = %d, stderr = %s", code, stderr)
	}
}

func TestRulesDir(t *testing.T) {
	rulesDir := writeTree(t, map[string]string{"JP-KEY-900.yaml": "id: JP-KEY-900\ntitle: Gateway token\nseverity: high\nverified: true\npattern: 'gw_[a-z0-9]{16}'\ndescription: A gateway token.\nremediation: Rotate it.\nrefs:\n  - https://example.com/x\n"})
	target := writeTree(t, map[string]string{"a.txt": "token gw_" + strings.Repeat("a", 16) + "\n"})
	code, stdout, stderr := runCLI(t, "scan", "--rules-dir", rulesDir, target)
	if code != exitFindings || !strings.Contains(stdout, "JP-KEY-900") {
		t.Errorf("code = %d, stdout = %s, stderr = %s", code, stdout, stderr)
	}

	duplicate := writeTree(t, map[string]string{"JP-KEY-001.yaml": "id: JP-KEY-001\ntitle: x\nseverity: low\nverified: true\nmatcher: x\ndescription: x\nremediation: x\n"})
	code, _, stderr = runCLI(t, "scan", "--rules-dir", duplicate, target)
	if code != exitUsage || !strings.Contains(stderr, "already defined") {
		t.Errorf("duplicate: code = %d, stderr = %s", code, stderr)
	}
}

func TestReportDefaultsToMarkdown(t *testing.T) {
	leaky := writeTree(t, map[string]string{".env": "ANTHROPIC_API_KEY=" + testKey + "\n"})
	code, stdout, _ := runCLI(t, "report", "--fail-on", "critical", leaky)
	if code != exitOK || !strings.Contains(stdout, "# jackproof report") || !strings.Contains(stdout, "## Coverage") {
		t.Errorf("code = %d, stdout = %s", code, stdout)
	}
}

func TestRulesCommands(t *testing.T) {
	code, stdout, _ := runCLI(t, "rules", "list")
	if code != exitOK || !strings.Contains(stdout, "JP-KEY-001") || !strings.Contains(stdout, "unverified") {
		t.Errorf("list: code = %d, stdout = %s", code, stdout)
	}
	code, stdout, _ = runCLI(t, "rules", "show", "jp-key-020")
	if code != exitOK || !strings.Contains(stdout, "pull_request_target") || !strings.Contains(stdout, "ref: https://") {
		t.Errorf("show: code = %d, stdout = %s", code, stdout)
	}
}

func exposureFixture(t *testing.T) (string, string) {
	t.Helper()
	key := "sk-" + strings.Repeat("b", 48)
	root := writeTree(t, map[string]string{
		".env":                     "OPENAI_API_KEY=" + key + "\n",
		"compose.yaml":             "services:\n  api:\n    env_file: .env\n",
		".github/workflows/ci.yml": "on: push\njobs:\n  j:\n    runs-on: x\n    env:\n      OPENAI_API_KEY: ${{ secrets.OPENAI_PROD_KEY }}\n    steps:\n      - run: echo\n",
	})
	return root, key
}

func TestExposureByFingerprintNameAndKey(t *testing.T) {
	root, key := exposureFixture(t)
	fingerprints := filepath.Join(t.TempDir(), "fingerprints.txt")
	if err := os.WriteFile(fingerprints, []byte("# from the provider\n"+secretFingerprint(key)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	names := filepath.Join(t.TempDir(), "names.txt")
	if err := os.WriteFile(names, []byte("OPENAI_PROD_KEY\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		args     []string
		input    string
		wantCode int
		want     []string
	}{
		{"fingerprint", []string{"exposure", "--fingerprints", fingerprints, root}, "", exitFindings, []string{"JP-EXP-001", "## Rotation plan", "**Revoke.**", "Deleting a stored secret does not revoke it"}},
		{"secret name", []string{"exposure", "--secret-names", names, root}, "", exitFindings, []string{"JP-EXP-001", "Secret name OPENAI_PROD_KEY"}},
		{"raw key on stdin", []string{"exposure", "--keys-stdin", root}, key + "\n", exitFindings, []string{"JP-EXP-001", "Fingerprint da681160a0224a55 (sha256)"}},
		{"not found", []string{"exposure", "--secret-names", names, t.TempDir()}, "", exitOK, []string{"JP-EXP-002"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, stdout, stderr := runCLIWithInput(t, tt.input, tt.args...)
			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d (stderr: %s)", code, tt.wantCode, stderr)
			}
			for _, want := range tt.want {
				if !strings.Contains(stdout, want) {
					t.Errorf("stdout lacks %q:\n%s", want, stdout)
				}
			}
			if strings.Contains(stdout, key) {
				t.Error("output contains the full key")
			}
		})
	}
}

func TestExposureJSONIncludesPlan(t *testing.T) {
	root, key := exposureFixture(t)
	code, stdout, stderr := runCLIWithInput(t, key+"\n", "exposure", "--keys-stdin", "--format", "json", "--fail-on", "critical", root)
	if code != exitOK {
		t.Fatalf("exit code = %d (stderr: %s)", code, stderr)
	}
	var decoded struct {
		Extras struct {
			RotationPlan struct {
				Statement   string
				Credentials []struct{ Steps []struct{ Phase string } }
			} `json:"rotation_plan"`
		}
	}
	if err := json.Unmarshal([]byte(stdout), &decoded); err != nil {
		t.Fatalf("output is not json: %v", err)
	}
	plan := decoded.Extras.RotationPlan
	if !strings.Contains(plan.Statement, "does not revoke") || len(plan.Credentials) != 1 || len(plan.Credentials[0].Steps) < 5 {
		t.Errorf("plan = %+v", plan)
	}
}

func TestExposureUsageErrors(t *testing.T) {
	root, _ := exposureFixture(t)
	badAlgo := filepath.Join(t.TempDir(), "f.txt")
	if err := os.WriteFile(badAlgo, []byte("abcd\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"no input", []string{"exposure", root}, "needs at least one of"},
		{"missing fingerprint file", []string{"exposure", "--fingerprints", filepath.Join(t.TempDir(), "none.txt"), root}, "read fingerprints"},
		{"malformed fingerprint", []string{"exposure", "--fingerprints", badAlgo, root}, "fingerprint must be"},
		{"verify without keys", []string{"exposure", "verify"}, "needs --keys-stdin"},
		{"verify without live flag", []string{"exposure", "verify", "--keys-stdin"}, "--verify-live"},
		{"verify without ownership", []string{"exposure", "verify", "--keys-stdin", "--verify-live"}, "--i-own-these-keys"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, _, stderr := runCLI(t, tt.args...)
			if code != exitUsage || !strings.Contains(stderr, tt.want) {
				t.Errorf("code = %d, stderr = %q, want it to contain %q", code, stderr, tt.want)
			}
		})
	}
}

func TestExposureVerifyWithoutNetwork(t *testing.T) {
	code, stdout, stderr := runCLIWithInput(t, "not a key\n", "exposure", "verify", "--keys-stdin", "--verify-live", "--i-own-these-keys")
	if code != exitFindings {
		t.Errorf("exit code = %d, want %d (stderr: %s)", code, exitFindings, stderr)
	}
	for _, want := range []string{"unsupported", "could not be identified", "Deleting a stored secret does not revoke it"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout lacks %q:\n%s", want, stdout)
		}
	}

	code, _, stderr = runCLIWithInput(t, "\n\n", "exposure", "verify", "--keys-stdin", "--verify-live", "--i-own-these-keys")
	if code != exitUsage || !strings.Contains(stderr, "no keys were provided") {
		t.Errorf("empty input: code = %d, stderr = %s", code, stderr)
	}
}

const postureFixture = "resource \"aws_iam_role\" \"deployer\" {\n  name = \"deployer\"\n}\n\nresource \"aws_iam_role_policy\" \"deployer\" {\n  role   = aws_iam_role.deployer.id\n  policy = jsonencode({\n    Statement = [{ Effect = \"Allow\", Action = [\"bedrock:*\"], Resource = \"*\" }]\n  })\n}\n"

func TestPostureCommand(t *testing.T) {
	root := writeTree(t, map[string]string{
		"prod/iam.tf":    postureFixture,
		"jackproof.yaml": "environments:\n  prod: [\"prod/**\"]\nexpected_providers:\n  prod: []\n",
	})
	code, stdout, stderr := runCLI(t, "posture", root)
	if code != exitFindings {
		t.Fatalf("exit code = %d (stderr: %s)", code, stderr)
	}
	for _, want := range []string{"JP-POS-001", "JP-POS-006", "jackproof posture:", "deployer can enable Amazon Bedrock", "files scanned: 1 (terraform 1)", "cloud permission entries"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout lacks %q:\n%s", want, stdout)
		}
	}
	code, stdout, _ = runCLI(t, "posture", "--format", "sarif", "--fail-on", "critical", root)
	if code != exitOK || !strings.Contains(stdout, `"ruleId": "JP-POS-001"`) {
		t.Errorf("sarif: code = %d, stdout = %.200s", code, stdout)
	}
	empty := t.TempDir()
	code, stdout, _ = runCLI(t, "posture", empty)
	if code != exitOK || !strings.Contains(stdout, "No findings") {
		t.Errorf("empty: code = %d, stdout = %s", code, stdout)
	}
}

func TestReportCombinesScanAndPosture(t *testing.T) {
	root := writeTree(t, map[string]string{
		"prod/iam.tf":    postureFixture,
		".env":           "ANTHROPIC_API_KEY=" + testKey + "\n",
		"jackproof.yaml": "environments:\n  prod: [\"prod/**\"]\nexpected_providers:\n  prod: []\n",
	})
	code, stdout, stderr := runCLI(t, "report", "--format", "json", "--fail-on", "critical", root)
	if code != exitOK {
		t.Fatalf("exit code = %d (stderr: %s)", code, stderr)
	}
	var decoded struct {
		Findings []struct{ Rule string }
		Coverage struct {
			FilesScanned map[string]int `json:"files_scanned"`
		}
	}
	if err := json.Unmarshal([]byte(stdout), &decoded); err != nil {
		t.Fatal(err)
	}
	rules := make(map[string]bool)
	for _, f := range decoded.Findings {
		rules[f.Rule] = true
	}
	if !rules["JP-KEY-001"] || !rules["JP-POS-001"] {
		t.Errorf("rules = %v", rules)
	}
	if decoded.Coverage.FilesScanned["terraform"] != 1 {
		t.Errorf("terraform files must be counted once: %+v", decoded.Coverage.FilesScanned)
	}
}

func trailRecord(id, name, source, time, ip string) string {
	return `{"eventID":"` + id + `","eventTime":"` + time + `","eventSource":"` + source + `","eventName":"` + name + `","awsRegion":"us-east-1","sourceIPAddress":"` + ip + `",` +
		`"userAgent":"sdk","recipientAccountId":"111122223333","userIdentity":{"arn":"arn:aws:iam::111122223333:role/chat","accountId":"111122223333"}}`
}

func TestHuntCommand(t *testing.T) {
	trail := `{"Records":[` + strings.Join([]string{
		trailRecord("e1", "PutFoundationModelEntitlement", "bedrock.amazonaws.com", "2026-03-01T10:00:00Z", "203.0.113.5"),
		trailRecord("e2", "InvokeModel", "bedrock.amazonaws.com", "2026-03-01T10:05:00Z", "203.0.113.5"),
		trailRecord("e3", "DescribeInstances", "ec2.amazonaws.com", "2026-03-01T10:06:00Z", "203.0.113.5"),
	}, ",") + `]}`
	dir := t.TempDir()
	logPath := filepath.Join(dir, "trail.json")
	if err := os.WriteFile(logPath, []byte(trail), 0o600); err != nil {
		t.Fatal(err)
	}

	code, stdout, stderr := runCLI(t, "hunt", "--source", "cloudtrail", logPath)
	if code != exitFindings {
		t.Fatalf("exit code = %d (stderr: %s)", code, stderr)
	}
	for _, want := range []string{"JP-HUNT-001", "e1 at 2026-03-01T10:00:00Z", "log source: cloudtrail: " + logPath + ", 2 relevant events", "time range for " + logPath + ": 2026-03-01T10:00:00Z to 2026-03-01T10:05:00Z"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout lacks %q:\n%s", want, stdout)
		}
	}

	code, stdout, _ = runCLI(t, "hunt", "--source", "cloudtrail", "--format", "json", "--fail-on", "critical", logPath)
	if code != exitOK || !strings.Contains(stdout, `"log_sources"`) || !strings.Contains(stdout, `"time_ranges"`) {
		t.Errorf("json: code = %d, stdout = %.300s", code, stdout)
	}

	graph := filepath.Join(dir, "scan.json")
	if err := os.WriteFile(graph, []byte(`{"graph":{"holders":[{"providers":["openai"]}]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, stdout, _ = runCLI(t, "hunt", "--source", "cloudtrail", "--graph", graph, "--fail-on", "critical", logPath)
	if !strings.Contains(stdout, "JP-HUNT-007") || !strings.Contains(stdout, "no scanned code calls that service") {
		t.Errorf("graph cross-reference missing:\n%s", stdout)
	}
}

func TestHuntUsageErrors(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "x.json")
	if err := os.WriteFile(logPath, []byte(`[]`), 0o600); err != nil {
		t.Fatal(err)
	}
	badGraph := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(badGraph, []byte(`not json`), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"no source", []string{"hunt", logPath}, "needs --source"},
		{"no files", []string{"hunt", "--source", "cloudtrail"}, "at least one log file"},
		{"unknown source", []string{"hunt", "--source", "syslog", logPath}, "unknown source type"},
		{"missing file", []string{"hunt", "--source", "cloudtrail", filepath.Join(dir, "absent.json")}, "read log file"},
		{"bad graph", []string{"hunt", "--source", "cloudtrail", "--graph", badGraph, logPath}, "--graph"},
		{"bad columns", []string{"hunt", "--source", "usage", "--usage-columns", "oops", logPath}, "--usage-columns"},
		{"missing network map", []string{"hunt", "--source", "cloudtrail", "--asn-map", filepath.Join(dir, "none.csv"), logPath}, "read network map"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, _, stderr := runCLI(t, tt.args...)
			if code != exitUsage || !strings.Contains(stderr, tt.want) {
				t.Errorf("code = %d, stderr = %q, want %q", code, stderr, tt.want)
			}
		})
	}
}

func TestHuntUsageCSVAndAzureNote(t *testing.T) {
	dir := t.TempDir()
	usage := filepath.Join(dir, "usage.csv")
	if err := os.WriteFile(usage, []byte("ts,key,requests\n2026-03-01T10:00:00Z,key-1,5\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runCLI(t, "hunt", "--source", "usage", "--usage-columns", "timestamp=ts,principal=key", usage)
	if code != exitOK || !strings.Contains(stdout, "1 relevant events") {
		t.Errorf("usage: code = %d, stdout = %s, stderr = %s", code, stdout, stderr)
	}
	azure := filepath.Join(dir, "activity.json")
	record := `[{"operationName":"Microsoft.CognitiveServices/accounts/write","caller":"c","eventTimestamp":"2026-03-01T10:00:00Z","status":"Succeeded"}]`
	if err := os.WriteFile(azure, []byte(record), 0o600); err != nil {
		t.Fatal(err)
	}
	_, stdout, _ = runCLI(t, "hunt", "--source", "azure", azure)
	if !strings.Contains(stdout, "does not record model invocations") {
		t.Errorf("azure note missing:\n%s", stdout)
	}
}

func TestExportSigmaCommand(t *testing.T) {
	root := writeTree(t, map[string]string{"jackproof.yaml": "hunt:\n  distinct_ips: 9\n"})
	code, stdout, stderr := runCLI(t, "hunt", "export-sigma", "--config", filepath.Join(root, "jackproof.yaml"))
	if code != exitOK || !strings.HasPrefix(stdout, "title: Bedrock model access enabled") || !strings.Contains(stdout, "gte: 9") || !strings.Contains(stdout, "\n---\n") {
		t.Errorf("code = %d, stderr = %s, stdout = %.200s", code, stderr, stdout)
	}
	if code, _, stderr := runCLI(t, "hunt", "export-sigma", "--bogus"); code != exitUsage || !strings.Contains(stderr, "hunt export-sigma") {
		t.Errorf("bad flag: code = %d, stderr = %s", code, stderr)
	}
}

func TestHTMLFormatFromTheCommandLine(t *testing.T) {
	leaky := writeTree(t, map[string]string{".env": "ANTHROPIC_API_KEY=" + testKey + "\n"})
	for _, command := range []string{"scan", "report"} {
		t.Run(command, func(t *testing.T) {
			code, stdout, stderr := runCLI(t, command, "--format", "html", "--fail-on", "critical", leaky)
			if code != exitOK {
				t.Fatalf("exit code = %d (stderr: %s)", code, stderr)
			}
			for _, want := range []string{"<!DOCTYPE html>", "JP-KEY-001", "Credential graph", "<h2>Coverage</h2>"} {
				if !strings.Contains(stdout, want) {
					t.Errorf("stdout lacks %q", want)
				}
			}
			if strings.Contains(stdout, testKey) {
				t.Error("the page contains the full key")
			}
		})
	}
}

func TestPostureLiveModeNeedsCredentialsAndRegion(t *testing.T) {
	dir := writeTree(t, map[string]string{"main.tf": "variable \"x\" {}\n"})
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	code, _, stderr := runCLI(t, "posture", "--live", dir)
	if code != exitUsage || !strings.Contains(stderr, "AWS_ACCESS_KEY_ID") {
		t.Errorf("no credentials: code = %d, stderr = %q", code, stderr)
	}

	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDEXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "example-secret")
	t.Setenv("AWS_REGION", "")
	t.Setenv("AWS_DEFAULT_REGION", "")
	code, _, stderr = runCLI(t, "posture", "--live", dir)
	if code != exitUsage || !strings.Contains(stderr, "needs a region") {
		t.Errorf("no region: code = %d, stderr = %q", code, stderr)
	}
	if strings.Contains(stderr, "example-secret") {
		t.Error("the error output contains the secret key")
	}

	code, stdout, _ := runCLI(t, "posture", "-h")
	if code != exitOK || !strings.Contains(stdout, "-live") || !strings.Contains(stdout, "-region") {
		t.Errorf("help: code = %d, stdout = %s", code, stdout)
	}
}
