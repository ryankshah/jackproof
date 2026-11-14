package scan

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/ryankshah/jackproof/internal/finding"
)

func gitCommand(t *testing.T, dir string, args ...string) {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", dir, "-c", "commit.gpgsign=false", "-c", "core.hooksPath=" + os.DevNull}, args...)...)
	command.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.invalid",
		"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.invalid")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, output)
	}
}

func TestLiteralKeyWordingFollowsGitState(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	line := "ANTHROPIC_API_KEY=" + anthropicKey + "\n"
	root := writeTree(t, map[string]string{
		".gitignore":          "ignored.env\n",
		"committed.env":       line,
		"ignored.env":         line,
		"later/untracked.env": line,
	})
	gitCommand(t, root, "init", "-q")
	gitCommand(t, root, "add", ".gitignore", "committed.env")
	gitCommand(t, root, "commit", "-q", "-m", "first")

	result, err := newScanner(t, "").Run([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	byPath := make(map[string]finding.Finding)
	for _, f := range findingsFor(result, "JP-KEY-001") {
		byPath[f.Evidence[0].Path] = f
	}
	tests := []struct {
		path         string
		wantTitle    string
		wantSeverity finding.Severity
		wantUnproven string
	}{
		{"committed.env", "committed in committed.env", finding.SeverityHigh, ""},
		{"later/untracked.env", "which git does not track yet", finding.SeverityHigh, "adding the whole directory"},
		{"ignored.env", "which git ignores", finding.SeverityLow, "not in the repository history"},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			f, ok := byPath[tt.path]
			if !ok {
				t.Fatalf("no finding for %s: %v", tt.path, byPath)
			}
			if !strings.Contains(f.Title, tt.wantTitle) || f.Severity != tt.wantSeverity {
				t.Errorf("title = %q, severity = %s", f.Title, f.Severity)
			}
			if tt.wantUnproven != "" && !strings.Contains(strings.Join(f.Unproven, " "), tt.wantUnproven) {
				t.Errorf("unproven = %v", f.Unproven)
			}
			if tt.wantUnproven == "" && strings.Contains(strings.Join(f.Unproven, " "), "git") {
				t.Errorf("a tracked file should carry no git caveat: %v", f.Unproven)
			}
			if err := f.Validate(); err != nil {
				t.Error(err)
			}
		})
	}
}

func TestLiteralKeyWordingOutsideAGitRepository(t *testing.T) {
	result := runScan(t, "", map[string]string{".env": "ANTHROPIC_API_KEY=" + anthropicKey + "\n"})
	found := findingsFor(result, "JP-KEY-001")
	if len(found) != 1 || !strings.Contains(found[0].Title, "found in .env") || found[0].Severity != finding.SeverityHigh {
		t.Errorf("findings = %+v", found)
	}
	if strings.Contains(found[0].Title, "committed") {
		t.Error("without git the scanner cannot claim the key is committed")
	}
}
