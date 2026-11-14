package scan

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/ryankshah/jackproof/internal/config"
	"github.com/ryankshah/jackproof/internal/finding"
	"github.com/ryankshah/jackproof/internal/scan/iac"
	"github.com/ryankshah/jackproof/internal/scan/lang"
)

const (
	maxFileSize     = 1 << 20
	binaryProbeSize = 8000
	readWorkers     = 16

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
	".git":          "version control metadata",
	"node_modules":  "third-party dependencies",
	"vendor":        "third-party dependencies",
	".venv":         "third-party dependencies",
	"venv":          "third-party dependencies",
	"__pycache__":   "compiled bytecode",
	".terraform":    "provider downloads",
	".gradle":       "build tool cache",
	".next":         "build tool cache",
	".nuxt":         "build tool cache",
	".cache":        "build tool cache",
	".tox":          "build tool cache",
	".mypy_cache":   "build tool cache",
	".pytest_cache": "build tool cache",
}

var buildOutputMarkers = map[string][]string{
	"build":  {"build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"},
	"target": {"pom.xml", "Cargo.toml"},
}

var binaryExtensions = map[string]bool{
	".class": true, ".jar": true, ".war": true, ".zip": true, ".gz": true, ".tgz": true, ".7z": true, ".rar": true, ".xz": true, ".bz2": true,
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".bmp": true, ".ico": true, ".webp": true, ".psd": true,
	".ogg": true, ".mp3": true, ".wav": true, ".mp4": true, ".mov": true, ".avi": true, ".flac": true,
	".ttf": true, ".otf": true, ".woff": true, ".woff2": true, ".eot": true,
	".pdf": true, ".exe": true, ".dll": true, ".so": true, ".dylib": true, ".bin": true, ".o": true, ".a": true, ".obj": true,
	".nbt": true, ".dat": true, ".mca": true, ".pyc": true, ".wasm": true,
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

type candidate struct {
	absolute string
	relative string
	entry    fs.DirEntry
}

type readResult struct {
	file *sourceFile
	skip string
	err  error
}

func collectFiles(roots []string, base string, cfg *config.Config, coverage *finding.Coverage) ([]*sourceFile, error) {
	var candidates []candidate
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
				return directoryDecision(entry.Name(), current, relative, current == absolute, cfg, coverage)
			}
			candidates = append(candidates, candidate{absolute: current, relative: relative, entry: entry})
			return nil
		})
		if walkErr != nil {
			return nil, walkErr
		}
	}

	results := readConcurrently(candidates, cfg)
	var files []*sourceFile
	for index, result := range results {
		switch {
		case result.err != nil:
			return nil, result.err
		case result.skip != "":
			coverage.AddSkipped(candidates[index].relative, result.skip)
		default:
			files = append(files, result.file)
		}
	}
	return files, nil
}

func readConcurrently(candidates []candidate, cfg *config.Config) []readResult {
	results := make([]readResult, len(candidates))
	indexes := make(chan int)
	var workers sync.WaitGroup
	for range readWorkers {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := range indexes {
				item := candidates[index]
				file, skip, err := readFile(item.absolute, item.relative, item.entry, cfg)
				results[index] = readResult{file: file, skip: skip, err: err}
			}
		}()
	}
	for index := range candidates {
		indexes <- index
	}
	close(indexes)
	workers.Wait()
	return results
}

func directoryDecision(name, absolute, relative string, isRoot bool, cfg *config.Config, coverage *finding.Coverage) error {
	if isRoot {
		return nil
	}
	if reason, skip := skippedDirectories[name]; skip {
		coverage.AddSkipped(relative+"/", reason)
		return fs.SkipDir
	}
	if isBuildOutput(absolute, name) {
		coverage.AddSkipped(relative+"/", "build output")
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
	if binaryExtensions[strings.ToLower(path.Ext(relative))] {
		return nil, "binary file", nil
	}
	data, binary, err := readText(absolute)
	if err != nil {
		return nil, "", fmt.Errorf("read %s: %w", relative, err)
	}
	if binary {
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

func isBuildOutput(absolute, name string) bool {
	for _, marker := range buildOutputMarkers[name] {
		if _, err := os.Stat(filepath.Join(filepath.Dir(absolute), marker)); err == nil {
			return true
		}
	}
	return false
}

func readText(absolute string) ([]byte, bool, error) {
	file, err := os.Open(absolute)
	if err != nil {
		return nil, false, fmt.Errorf("open file: %w", err)
	}
	defer func() { _ = file.Close() }()
	head := make([]byte, binaryProbeSize)
	count, err := io.ReadFull(file, head)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, false, fmt.Errorf("read file: %w", err)
	}
	head = head[:count]
	if bytes.IndexByte(head, 0) >= 0 {
		return nil, true, nil
	}
	rest, err := io.ReadAll(file)
	if err != nil {
		return nil, false, fmt.Errorf("read file: %w", err)
	}
	return append(head, rest...), false, nil
}
