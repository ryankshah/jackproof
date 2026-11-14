package main

import (
	"go/scanner"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

const repositoryRoot = "../.."

var bannedPhrases = []string{
	"blazingly fast", "powerful", "seamless", "robust", "leverage", "unlock", "comprehensive",
	"cutting-edge", "game-changer", "delve", "in today's landscape", "it's worth noting", "simply",
	"whether you're",
}

var emoji = regexp.MustCompile(`[\x{1F300}-\x{1FAFF}\x{2600}-\x{27BF}\x{1F000}-\x{1F2FF}]`)

func repositoryFiles(t *testing.T, match func(path string) bool) []string {
	t.Helper()
	var files []string
	err := filepath.WalkDir(repositoryRoot, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			name := entry.Name()
			if path != repositoryRoot && strings.HasPrefix(name, ".") && name != ".github" && name != ".githooks" {
				return fs.SkipDir
			}
			switch name {
			case "bin", "dist":
				return fs.SkipDir
			}
			return nil
		}
		relative, _ := filepath.Rel(repositoryRoot, path)
		if match(filepath.ToSlash(relative)) {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func TestGoSourceHasNoComments(t *testing.T) {
	files := repositoryFiles(t, func(path string) bool { return strings.HasSuffix(path, ".go") })
	if len(files) == 0 {
		t.Fatal("no go files found")
	}
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		fileSet := token.NewFileSet()
		file := fileSet.AddFile(path, fileSet.Base(), len(data))
		var lexer scanner.Scanner
		lexer.Init(file, data, nil, scanner.ScanComments)
		for {
			position, kind, literal := lexer.Scan()
			if kind == token.EOF {
				break
			}
			if kind == token.COMMENT && !strings.HasPrefix(literal, "//go:") {
				t.Errorf("%s: comment %q", fileSet.Position(position), literal)
			}
		}
	}
}

func TestNonGoFilesHaveNoComments(t *testing.T) {
	files := repositoryFiles(t, func(path string) bool {
		base := filepath.Base(path)
		switch {
		case strings.HasPrefix(path, "rules/") && strings.HasSuffix(path, ".yaml"):
			return true
		case strings.HasSuffix(path, ".yml"), strings.HasSuffix(path, ".yaml"), strings.HasSuffix(path, ".sh"), strings.HasSuffix(path, ".ps1"), strings.HasSuffix(path, ".tmpl"):
			return true
		}
		return base == "Dockerfile" || base == "Makefile" || path == ".githooks/commit-msg"
	})
	if len(files) < 8 {
		t.Fatalf("only %d files found", len(files))
	}
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for number, line := range strings.Split(string(data), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "#") && !strings.HasPrefix(trimmed, "#!") {
				t.Errorf("%s:%d: comment %q", path, number+1, trimmed)
			}
		}
	}
}

func checkProse(t *testing.T, name, text string) {
	t.Helper()
	if strings.Contains(text, "—") {
		t.Errorf("%s contains an em dash", name)
	}
	if emoji.MatchString(text) {
		t.Errorf("%s contains an emoji", name)
	}
	lower := strings.ToLower(text)
	for _, phrase := range bannedPhrases {
		if strings.Contains(lower, phrase) {
			t.Errorf("%s contains the banned phrase %q", name, phrase)
		}
	}
}

var (
	codeFence  = regexp.MustCompile("(?s)```.*?```")
	inlineCode = regexp.MustCompile("`[^`\n]*`")
)

func TestDocumentsFollowTheWritingRules(t *testing.T) {
	files := repositoryFiles(t, func(path string) bool {
		return strings.HasSuffix(path, ".md")
	})
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		checkProse(t, path, string(data))
		prose := inlineCode.ReplaceAllString(codeFence.ReplaceAllString(string(data), ""), "")
		if regexp.MustCompile(`!(\s|$)`).MatchString(prose) {
			t.Errorf("%s contains an exclamation mark in prose", path)
		}
		if regexp.MustCompile(`\?\s*(\n|$)`).MatchString(prose) {
			t.Errorf("%s contains a question mark at the end of a sentence", path)
		}
	}
}

func TestRulesAndMessagesFollowTheWritingRules(t *testing.T) {
	for _, path := range repositoryFiles(t, func(path string) bool { return strings.HasPrefix(path, "rules/") && strings.HasSuffix(path, ".yaml") }) {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		checkProse(t, path, string(data))
		if strings.Contains(string(data), "!") {
			t.Errorf("%s contains an exclamation mark", path)
		}
	}
	for _, path := range repositoryFiles(t, func(path string) bool {
		return strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go")
	}) {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		fileSet := token.NewFileSet()
		file := fileSet.AddFile(path, fileSet.Base(), len(data))
		var lexer scanner.Scanner
		lexer.Init(file, data, nil, 0)
		for {
			position, kind, literal := lexer.Scan()
			if kind == token.EOF {
				break
			}
			if kind == token.STRING {
				checkProse(t, fileSet.Position(position).String(), literal)
			}
		}
	}
}

func TestCommitMessageHook(t *testing.T) {
	shell, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh is not available")
	}
	hook := filepath.Join(repositoryRoot, ".githooks", "commit-msg")
	tests := []struct {
		name    string
		message string
		reject  bool
	}{
		{"clean message", "feat(scan): detect keys\n\nBody text.\n", false},
		{"co-author trailer", "feat: x\n\nCo-Authored-By: someone\n", true},
		{"co-author in lower case", "feat: x\n\nco-authored-by: someone\n", true},
		{"generated footer", "feat: x\n\nGenerated with a tool\n", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			message := filepath.Join(t.TempDir(), "message")
			if err := os.WriteFile(message, []byte(tt.message), 0o600); err != nil {
				t.Fatal(err)
			}
			err := exec.Command(shell, hook, message).Run()
			if (err != nil) != tt.reject {
				t.Errorf("hook error = %v, want rejection = %v", err, tt.reject)
			}
		})
	}
}

func readYAML(t *testing.T, name string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repositoryRoot, name))
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := yaml.Unmarshal(data, &document); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return document
}

func TestGitHubAction(t *testing.T) {
	action := readYAML(t, "action.yml")
	inputs := action["inputs"].(map[string]any)
	for _, name := range []string{"version", "fail-on", "strict", "comment", "upload-sarif", "github-token"} {
		if _, ok := inputs[name]; !ok {
			t.Errorf("action input %q is missing", name)
		}
	}
	if inputs["strict"].(map[string]any)["default"] != "false" {
		t.Error("strict mode must be off by default")
	}
	if action["runs"].(map[string]any)["using"] != "composite" {
		t.Error("the action must be a composite action")
	}
	data, _ := os.ReadFile(filepath.Join(repositoryRoot, "action.yml"))
	for _, want := range []string{"jackproof\" diff", "upload-sarif", "pr-comment.sh", "--fail-on"} {
		if !strings.Contains(string(data), want) {
			t.Errorf("action.yml lacks %q", want)
		}
	}
	script, err := os.ReadFile(filepath.Join(repositoryRoot, "scripts", "pr-comment.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(script), "<!-- jackproof -->") || !strings.Contains(string(script), "PATCH") {
		t.Error("the comment script must update an existing comment that carries the marker")
	}
}

func TestPreCommitHook(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repositoryRoot, ".pre-commit-hooks.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var hooks []map[string]any
	if err := yaml.Unmarshal(data, &hooks); err != nil {
		t.Fatal(err)
	}
	if len(hooks) != 1 || hooks[0]["id"] != "jackproof-scan" || !strings.Contains(hooks[0]["entry"].(string), "scan --staged") || hooks[0]["language"] != "golang" {
		t.Errorf("hooks = %+v", hooks)
	}
}

func TestReleaseConfiguration(t *testing.T) {
	config := readYAML(t, ".goreleaser.yaml")
	if config["version"] != 2 {
		t.Errorf("version = %v", config["version"])
	}
	build := config["builds"].([]any)[0].(map[string]any)
	if got := build["goos"].([]any); len(got) != 3 {
		t.Errorf("goos = %v", got)
	}
	if got := build["goarch"].([]any); len(got) != 2 {
		t.Errorf("goarch = %v", got)
	}
	if env := build["env"].([]any); len(env) != 1 || env[0] != "CGO_ENABLED=0" {
		t.Errorf("env = %v", env)
	}
	for _, key := range []string{"checksum", "sboms", "homebrew_casks", "archives"} {
		if _, ok := config[key]; !ok {
			t.Errorf("%s is missing from the release configuration", key)
		}
	}
	if config["release"].(map[string]any)["draft"] != true {
		t.Error("releases must be drafts until the owner publishes them")
	}
}

func TestDockerfile(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repositoryRoot, "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{"gcr.io/distroless/static-debian12:nonroot", "USER nonroot:nonroot", "CGO_ENABLED=0", "ENTRYPOINT"} {
		if !strings.Contains(text, want) {
			t.Errorf("Dockerfile lacks %q", want)
		}
	}
}
