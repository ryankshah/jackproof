package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func gitIn(t *testing.T, dir string, args ...string) string {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", dir, "-c", "commit.gpgsign=false", "-c", "core.hooksPath=" + os.DevNull}, args...)...)
	command.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.invalid",
		"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.invalid")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, output)
	}
	return strings.TrimSpace(string(output))
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	path := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func twoCommitRepository(t *testing.T) (repository, first, second string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	repository = t.TempDir()
	gitIn(t, repository, "init", "-q")
	writeFile(t, repository, "main.go", "package main\n")
	gitIn(t, repository, "add", "-A")
	gitIn(t, repository, "commit", "-q", "-m", "first")
	first = gitIn(t, repository, "rev-parse", "HEAD")

	writeFile(t, repository, ".env", "ANTHROPIC_API_KEY="+testKey+"\n")
	gitIn(t, repository, "add", "-A")
	gitIn(t, repository, "commit", "-q", "-m", "second")
	second = gitIn(t, repository, "rev-parse", "HEAD")
	t.Chdir(repository)
	return repository, first, second
}

func TestDiffReportsFindingsAddedInHead(t *testing.T) {
	repository, first, second := twoCommitRepository(t)

	code, stdout, stderr := runCLI(t, "diff", first, second)
	if code != exitFindings {
		t.Fatalf("exit code = %d (stderr: %s)", code, stderr)
	}
	for _, want := range []string{"JP-KEY-001", "Added: 1. Removed: 0. Changed: 0. Unchanged: 0.", "findings added in the head revision"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout lacks %q:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, testKey) {
		t.Error("output contains the full key")
	}

	code, stdout, _ = runCLI(t, "diff", second, first)
	if code != exitOK || !strings.Contains(stdout, "Removed: 1") || !strings.Contains(stdout, "- removed high JP-KEY-001") {
		t.Errorf("reverse: code = %d, stdout = %s", code, stdout)
	}

	code, stdout, _ = runCLI(t, "diff", second, second)
	if code != exitOK || !strings.Contains(stdout, "Unchanged: 1") {
		t.Errorf("same revision: code = %d, stdout = %s", code, stdout)
	}

	code, stdout, _ = runCLI(t, "diff", "--format", "json", first, second)
	var decoded struct {
		Findings []struct{ Rule string }
		Extras   struct{ Diff diffSummary }
	}
	if err := json.Unmarshal([]byte(stdout), &decoded); err != nil || code != exitFindings {
		t.Fatalf("json: code = %d, err = %v", code, err)
	}
	if len(decoded.Findings) != 1 || decoded.Extras.Diff.Added != 1 {
		t.Errorf("decoded = %+v", decoded)
	}

	if list := gitIn(t, repository, "worktree", "list"); strings.Contains(list, "jackproof-worktree") {
		t.Errorf("a worktree was left behind: %s", list)
	}
}

func TestDiffUsageErrors(t *testing.T) {
	_, first, _ := twoCommitRepository(t)
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"one revision", []string{"diff", first}, "needs a base revision and a head revision"},
		{"unknown revision", []string{"diff", first, "no-such-revision"}, "resolve revision"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, _, stderr := runCLI(t, tt.args...)
			if code != exitUsage || !strings.Contains(stderr, tt.want) {
				t.Errorf("code = %d, stderr = %q", code, stderr)
			}
		})
	}
	t.Chdir(t.TempDir())
	if code, _, stderr := runCLI(t, "diff", "a", "b"); code != exitUsage || !strings.Contains(stderr, "repository root") {
		t.Errorf("outside a repository: code = %d, stderr = %q", code, stderr)
	}
}

func TestScanStagedUsesTheIndexNotTheWorkingTree(t *testing.T) {
	repository, _, _ := twoCommitRepository(t)
	writeFile(t, repository, "leak.txt", "token "+testKey+"\n")
	gitIn(t, repository, "add", "leak.txt")
	writeFile(t, repository, "leak.txt", "the key was removed after staging\n")
	writeFile(t, repository, "untracked.txt", "token "+testKey+"\n")

	code, stdout, stderr := runCLI(t, "scan", "--staged")
	if code != exitFindings {
		t.Fatalf("exit code = %d (stderr: %s)", code, stderr)
	}
	if !strings.Contains(stdout, "leak.txt:1") || strings.Contains(stdout, "untracked.txt") || strings.Contains(stdout, ".env:1") {
		t.Errorf("only the staged file may be scanned:\n%s", stdout)
	}

	gitIn(t, repository, "reset", "-q")
	code, stdout, _ = runCLI(t, "scan", "--staged")
	if code != exitOK || !strings.Contains(stdout, "No findings") {
		t.Errorf("nothing staged: code = %d, stdout = %s", code, stdout)
	}

	if code, _, stderr := runCLI(t, "scan", "--staged", "src"); code != exitUsage || !strings.Contains(stderr, "does not take paths") {
		t.Errorf("paths with --staged: code = %d, stderr = %q", code, stderr)
	}
	t.Chdir(t.TempDir())
	if code, _, _ := runCLI(t, "scan", "--staged"); code != exitUsage {
		t.Errorf("outside a repository: code = %d", code)
	}
}

func TestExplain(t *testing.T) {
	root := writeTree(t, map[string]string{".env": "ANTHROPIC_API_KEY=" + testKey + "\n"})
	_, stdout, _ := runCLI(t, "scan", "--format", "json", "--fail-on", "critical", root)
	var decoded struct {
		Findings []struct{ ID string }
	}
	if err := json.Unmarshal([]byte(stdout), &decoded); err != nil || len(decoded.Findings) != 1 {
		t.Fatalf("scan output: %v, %s", err, stdout)
	}
	id := decoded.Findings[0].ID
	report := filepath.Join(t.TempDir(), "scan.json")
	if err := os.WriteFile(report, []byte(stdout), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		args []string
	}{
		{"rescan", []string{"explain", id, root}},
		{"saved report with a prefix", []string{"explain", "--from", report, id[:8]}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, stdout, stderr := runCLI(t, tt.args...)
			if code != exitOK {
				t.Fatalf("exit code = %d (stderr: %s)", code, stderr)
			}
			for _, want := range []string{id, "JP-KEY-001", "evidence", ".env:1-1", "not established", "fix", "not verified against provider documentation", "references"} {
				if !strings.Contains(stdout, want) {
					t.Errorf("stdout lacks %q:\n%s", want, stdout)
				}
			}
			if strings.Contains(stdout, testKey) {
				t.Error("output contains the full key")
			}
		})
	}

	code, stdout, _ := runCLI(t, "explain", "--from", report, "--format", "json", id)
	var single struct{ ID, Rule string }
	if code != exitOK || json.Unmarshal([]byte(stdout), &single) != nil || single.ID != id || single.Rule != "JP-KEY-001" {
		t.Errorf("json: code = %d, stdout = %s", code, stdout)
	}
}

func TestExplainErrors(t *testing.T) {
	root := writeTree(t, map[string]string{"main.go": "package main\n"})
	notJSON := filepath.Join(t.TempDir(), "x.json")
	if err := os.WriteFile(notJSON, []byte("nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"no id", []string{"explain"}, "needs a finding id"},
		{"short id", []string{"explain", "abc"}, "at least 6 characters"},
		{"unknown id", []string{"explain", "ffffffffffff", root}, "no finding has the id"},
		{"bad report", []string{"explain", "--from", notJSON, "ffffffffffff"}, "--from"},
		{"missing report", []string{"explain", "--from", filepath.Join(t.TempDir(), "absent.json"), "ffffffffffff"}, "read report"},
		{"unsupported format", []string{"explain", "--format", "sarif", "ffffffffffff"}, "text and json"},
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

func TestFindByIDAmbiguousPrefix(t *testing.T) {
	findings := readTestFindings(t, `{"findings":[{"id":"abcdef000001"},{"id":"abcdef000002"}]}`)
	if _, err := findByID(findings, "abcdef"); err == nil || !strings.Contains(err.Error(), "matches 2 findings") {
		t.Errorf("error = %v", err)
	}
	if match, err := findByID(findings, "abcdef000002"); err != nil || match.ID != "abcdef000002" {
		t.Errorf("match = %+v, err = %v", match, err)
	}
}
