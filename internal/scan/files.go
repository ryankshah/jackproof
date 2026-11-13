package scan

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ryankshah/jackproof/internal/config"
	"github.com/ryankshah/jackproof/internal/finding"
	"github.com/ryankshah/jackproof/internal/scan/iac"
	"github.com/ryankshah/jackproof/internal/scan/lang"
)

const (
	maxFileSize     = 1 << 20
	binaryProbeSize = 8000

	kindDotenv       = "dotenv"
	kindDockerignore = "dockerignore"
	kindDockerfile   = "dockerfile"
	kindDevcontainer = "devcontainer"
	kindNotebook     = "notebook"
	kindActions      = "github-actions"
	kindCompose      = "compose"
	kindKubernetes   = "kubernetes"
	kindTerraform    = "terraform"
	kindText         = "text"
)

var skippedDirectories = map[string]string{
	".git":         "version control metadata",
	"node_modules": "third-party dependencies",
	"vendor":       "third-party dependencies",
	".venv":        "third-party dependencies",
	"venv":         "third-party dependencies",
	"__pycache__":  "compiled bytecode",
	".terraform":   "provider downloads",
}

var composeName = regexp.MustCompile(`^(?:docker-)?compose(?:[.-].+)?\.ya?ml$`)

type sourceFile struct {
	path  string
	kind  string
	data  []byte
	lines []string
}

func (f *sourceFile) line(number int) string {
	if f.lines == nil {
		f.lines = strings.Split(strings.ReplaceAll(string(f.data), "\r\n", "\n"), "\n")
	}
	if number < 1 || number > len(f.lines) {
		return ""
	}
	return f.lines[number-1]
}

func baseDirectory(root string) (string, error) {
	absolute, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", root, err)
	}
	info, err := os.Stat(absolute)
	if err != nil {
		return "", fmt.Errorf("stat %s: %w", root, err)
	}
	if !info.IsDir() {
		return filepath.Dir(absolute), nil
	}
	return absolute, nil
}

func collectFiles(roots []string, base string, cfg *config.Config, coverage *finding.Coverage) ([]*sourceFile, error) {
	var files []*sourceFile
	for _, root := range roots {
		absolute, err := filepath.Abs(root)
		if err != nil {
			return nil, fmt.Errorf("resolve %s: %w", root, err)
		}
		walkErr := filepath.WalkDir(absolute, func(current string, entry fs.DirEntry, err error) error {
			if err != nil {
				return fmt.Errorf("walk %s: %w", current, err)
			}
			relative, relErr := filepath.Rel(base, current)
			if relErr != nil {
				return fmt.Errorf("relative path for %s: %w", current, relErr)
			}
			relative = filepath.ToSlash(relative)
			if entry.IsDir() {
				return directoryDecision(entry.Name(), relative, current == absolute, cfg, coverage)
			}
			file, skipReason, readErr := readFile(current, relative, entry, cfg)
			switch {
			case readErr != nil:
				return readErr
			case skipReason != "":
				coverage.AddSkipped(relative, skipReason)
			default:
				files = append(files, file)
			}
			return nil
		})
		if walkErr != nil {
			return nil, walkErr
		}
	}
	return files, nil
}

func directoryDecision(name, relative string, isRoot bool, cfg *config.Config, coverage *finding.Coverage) error {
	if isRoot {
		return nil
	}
	if reason, skip := skippedDirectories[name]; skip {
		coverage.AddSkipped(relative+"/", reason)
		return fs.SkipDir
	}
	if cfg.IgnoresPath(relative + "/x") {
		coverage.AddSkipped(relative+"/", "ignored by configuration")
		return fs.SkipDir
	}
	return nil
}

func readFile(absolute, relative string, entry fs.DirEntry, cfg *config.Config) (*sourceFile, string, error) {
	if cfg.IgnoresPath(relative) {
		return nil, "ignored by configuration", nil
	}
	if entry.Type()&fs.ModeSymlink != 0 {
		return nil, "symbolic link", nil
	}
	if !entry.Type().IsRegular() {
		return nil, "not a regular file", nil
	}
	info, err := entry.Info()
	if err != nil {
		return nil, "", fmt.Errorf("stat %s: %w", relative, err)
	}
	if info.Size() > maxFileSize {
		return nil, fmt.Sprintf("larger than %d bytes", maxFileSize), nil
	}
	data, err := os.ReadFile(absolute)
	if err != nil {
		return nil, "", fmt.Errorf("read %s: %w", relative, err)
	}
	if bytes.IndexByte(data[:min(len(data), binaryProbeSize)], 0) >= 0 {
		return nil, "binary file", nil
	}
	return &sourceFile{path: relative, kind: classify(relative, data), data: data}, "", nil
}

func classify(filePath string, data []byte) string {
	lower := strings.ToLower(path.Base(filePath))
	extension := path.Ext(lower)
	switch {
	case isDotenvName(lower):
		return kindDotenv
	case lower == ".dockerignore":
		return kindDockerignore
	case lower == "dockerfile" || strings.HasPrefix(lower, "dockerfile.") || strings.HasSuffix(lower, ".dockerfile"):
		return kindDockerfile
	case lower == "devcontainer.json" || lower == ".devcontainer.json":
		return kindDevcontainer
	case extension == ".ipynb":
		return kindNotebook
	case (extension == ".yml" || extension == ".yaml") && strings.Contains(filePath, ".github/workflows/"):
		return kindActions
	case composeName.MatchString(lower):
		return kindCompose
	case extension == ".tf" || extension == ".tfvars":
		return kindTerraform
	}
	if language, ok := lang.LanguageFor(filePath); ok {
		return language
	}
	if (extension == ".yml" || extension == ".yaml" || extension == ".json") && iac.IsKubernetes(data) {
		return kindKubernetes
	}
	return kindText
}

func isExampleFile(filePath string) bool {
	lower := strings.ToLower(path.Base(filePath))
	for _, marker := range []string{"example", "sample", "template"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}
