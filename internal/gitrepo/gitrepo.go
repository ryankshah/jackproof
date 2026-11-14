package gitrepo

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const commandTimeout = 2 * time.Minute

func run(dir string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		var missing *exec.Error
		if errors.As(err, &missing) {
			return "", fmt.Errorf("git is not installed or not on the path: %w", err)
		}
		return "", fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

func Toplevel(dir string) (string, error) {
	output, err := run(dir, "rev-parse", "--show-toplevel")
	if err != nil {
		return "", fmt.Errorf("find the repository root: %w", err)
	}
	return filepath.FromSlash(strings.TrimSpace(output)), nil
}

func Resolve(dir, revision string) (string, error) {
	output, err := run(dir, "rev-parse", "--verify", "--end-of-options", revision+"^{commit}")
	if err != nil {
		return "", fmt.Errorf("resolve revision %q: %w", revision, err)
	}
	return strings.TrimSpace(output), nil
}

func Checkout(repository, revision string) (string, func() error, error) {
	commit, err := Resolve(repository, revision)
	if err != nil {
		return "", nil, err
	}
	parent, err := os.MkdirTemp("", "jackproof-worktree-")
	if err != nil {
		return "", nil, fmt.Errorf("create a temporary directory: %w", err)
	}
	target := filepath.Join(parent, "tree")
	if _, err := run(repository, "worktree", "add", "--detach", "--force", target, commit); err != nil {
		_ = os.RemoveAll(parent)
		return "", nil, fmt.Errorf("check out %s: %w", revision, err)
	}
	cleanup := func() error {
		_, removeErr := run(repository, "worktree", "remove", "--force", target)
		pruneErr := os.RemoveAll(parent)
		return errors.Join(removeErr, pruneErr)
	}
	return target, cleanup, nil
}

func StagedFiles(repository string) ([]string, error) {
	output, err := run(repository, "diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z")
	if err != nil {
		return nil, fmt.Errorf("list staged files: %w", err)
	}
	var files []string
	for _, name := range strings.Split(output, "\x00") {
		if name != "" {
			files = append(files, name)
		}
	}
	return files, nil
}

func StageSnapshot(repository string, files []string) (string, func() error, error) {
	directory, err := os.MkdirTemp("", "jackproof-staged-")
	if err != nil {
		return "", nil, fmt.Errorf("create a temporary directory: %w", err)
	}
	cleanup := func() error { return os.RemoveAll(directory) }
	if len(files) == 0 {
		return directory, cleanup, nil
	}
	prefix := directory + string(os.PathSeparator)
	arguments := append([]string{"checkout-index", "--prefix=" + prefix, "--"}, files...)
	if _, err := run(repository, arguments...); err != nil {
		_ = cleanup()
		return "", nil, fmt.Errorf("export staged files: %w", err)
	}
	return directory, cleanup, nil
}

type FileState int

const (
	Tracked FileState = iota + 1
	Untracked
)

func FileStates(directory string) (map[string]FileState, bool) {
	tracked, err := run(directory, "ls-files", "-z")
	if err != nil {
		return nil, false
	}
	untracked, err := run(directory, "ls-files", "-z", "--others", "--exclude-standard")
	if err != nil {
		return nil, false
	}
	states := make(map[string]FileState)
	for _, name := range strings.Split(untracked, "\x00") {
		if name != "" {
			states[name] = Untracked
		}
	}
	for _, name := range strings.Split(tracked, "\x00") {
		if name != "" {
			states[name] = Tracked
		}
	}
	return states, true
}
