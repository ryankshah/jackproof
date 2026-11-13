package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var (
	fencedBlock = regexp.MustCompile("(?s)```[a-z]*\n(.*?)```")
	heredoc     = regexp.MustCompile(`(?s)cat > (\S+) <<'EOF'\n(.*?)\nEOF\n`)
)

func readmeBlocks(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repositoryRoot, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	var blocks []string
	for _, match := range fencedBlock.FindAllStringSubmatch(text, -1) {
		blocks = append(blocks, match[1])
	}
	return blocks
}

func blockWith(t *testing.T, blocks []string, command string) (string, string) {
	t.Helper()
	for index, block := range blocks {
		for _, line := range strings.Split(block, "\n") {
			if (line == command || strings.HasSuffix(line, "| "+command)) && index+1 < len(blocks) {
				return block, blocks[index+1]
			}
		}
	}
	t.Fatalf("README has no command block containing %q", command)
	return "", ""
}

func TestReadmeQuickstartsMatchTheBinary(t *testing.T) {
	blocks := readmeBlocks(t)
	key := "sk-" + "ant-" + strings.Repeat("x", 90)

	tests := []struct {
		name    string
		command string
		args    []string
		input   string
		files   map[string]string
	}{
		{"scan", "jackproof scan .", []string{"scan", "."}, "", map[string]string{".env": "ANTHROPIC_API_KEY=" + key + "\n"}},
		{"posture", "jackproof posture .", []string{"posture", "."}, "", nil},
		{"exposure", "jackproof exposure --keys-stdin --format text .", []string{"exposure", "--keys-stdin", "--format", "text", "."}, key + "\n", map[string]string{".env": "ANTHROPIC_API_KEY=" + key + "\n"}},
		{"hunt", "jackproof hunt --source cloudtrail trail.json", []string{"hunt", "--source", "cloudtrail", "trail.json"}, "", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			commands, want := blockWith(t, blocks, tt.command)
			files := make(map[string]string)
			for name, content := range tt.files {
				files[name] = content
			}
			for _, match := range heredoc.FindAllStringSubmatch(commands, -1) {
				files[match[1]] = match[2] + "\n"
			}
			dir := writeTree(t, files)
			t.Chdir(dir)

			code, stdout, stderr := runCLIWithInput(t, tt.input, tt.args...)
			if code == exitUsage {
				t.Fatalf("the quickstart command failed: %s", stderr)
			}
			if stdout != want {
				t.Errorf("the README output does not match the binary.\n--- README ---\n%s\n--- binary ---\n%s", want, stdout)
			}
		})
	}
}

func TestReadmeSetupCommandsBuildTheFixtureUsedByTheTest(t *testing.T) {
	blocks := readmeBlocks(t)
	commands, _ := blockWith(t, blocks, "jackproof scan .")
	for _, want := range []string{`KEY="sk-ant-$(printf 'x%.0s' $(seq 1 90))"`, `printf 'ANTHROPIC_API_KEY=%s\n' "$KEY" > .env`} {
		if !strings.Contains(commands, want) {
			t.Errorf("the scan quickstart lacks %q", want)
		}
	}
	exposure, _ := blockWith(t, blocks, "jackproof exposure --keys-stdin --format text .")
	if !strings.Contains(exposure, `printf '%s\n' "$KEY" | jackproof exposure`) {
		t.Error("the exposure quickstart must pipe the same key into the command")
	}
}

func TestReadmeStaysShort(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repositoryRoot, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	if lines := strings.Count(string(data), "\n"); lines >= 250 {
		t.Errorf("README has %d lines, want fewer than 250", lines)
	}
}
