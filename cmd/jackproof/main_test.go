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
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
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
