package gitrepo

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func git(t *testing.T, dir string, args ...string) string {
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

func write(t *testing.T, dir, name, content string) {
	t.Helper()
	path := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func newRepository(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	dir := t.TempDir()
	git(t, dir, "init", "-q")
	return dir
}

func TestToplevelAndResolve(t *testing.T) {
	repository := newRepository(t)
	write(t, repository, "sub/a.txt", "one")
	git(t, repository, "add", "-A")
	git(t, repository, "commit", "-q", "-m", "first")

	top, err := Toplevel(filepath.Join(repository, "sub"))
	if err != nil {
		t.Fatal(err)
	}
	if want, _ := filepath.EvalSymlinks(repository); !strings.EqualFold(filepath.Clean(top), filepath.Clean(want)) {
		t.Errorf("toplevel = %q, want %q", top, want)
	}
	if _, err := Toplevel(t.TempDir()); err == nil {
		t.Error("expected an error outside a repository")
	}

	head := git(t, repository, "rev-parse", "HEAD")
	if resolved, err := Resolve(repository, "HEAD"); err != nil || resolved != head {
		t.Errorf("resolved = %q, %v, want %q", resolved, err, head)
	}
	if _, err := Resolve(repository, "no-such-revision"); err == nil {
		t.Error("expected an error for an unknown revision")
	}
	if _, err := Resolve(repository, "--upload-pack=x"); err == nil {
		t.Error("a revision that looks like an option must be rejected")
	}
}

func TestCheckoutIsIsolatedAndCleansUp(t *testing.T) {
	repository := newRepository(t)
	write(t, repository, "app.txt", "old")
	git(t, repository, "add", "-A")
	git(t, repository, "commit", "-q", "-m", "first")
	first := git(t, repository, "rev-parse", "HEAD")
	write(t, repository, "app.txt", "new")
	write(t, repository, "added.txt", "x")
	git(t, repository, "add", "-A")
	git(t, repository, "commit", "-q", "-m", "second")

	path, cleanup, err := Checkout(repository, first)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(path, "app.txt"))
	if err != nil || string(data) != "old" {
		t.Errorf("worktree content = %q, %v", data, err)
	}
	if _, err := os.Stat(filepath.Join(path, "added.txt")); err == nil {
		t.Error("the later commit's file is present in the older worktree")
	}
	current, _ := os.ReadFile(filepath.Join(repository, "app.txt"))
	if string(current) != "new" {
		t.Error("the working tree was modified")
	}
	if err := cleanup(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err == nil {
		t.Error("the worktree directory still exists after cleanup")
	}
	if list := git(t, repository, "worktree", "list"); strings.Count(list, "\n") != 0 {
		t.Errorf("worktree list = %q", list)
	}
	if _, _, err := Checkout(repository, "no-such-revision"); err == nil {
		t.Error("expected an error for an unknown revision")
	}
}

func TestStagedFilesAndSnapshot(t *testing.T) {
	repository := newRepository(t)
	write(t, repository, "keep.txt", "keep")
	write(t, repository, "gone.txt", "gone")
	git(t, repository, "add", "-A")
	git(t, repository, "commit", "-q", "-m", "first")

	write(t, repository, "keep.txt", "staged change")
	write(t, repository, "dir/new file.txt", "added")
	git(t, repository, "rm", "-q", "gone.txt")
	git(t, repository, "add", "keep.txt", "dir/new file.txt")
	write(t, repository, "keep.txt", "unstaged edit on top")
	write(t, repository, "untracked.txt", "never staged")

	files, err := StagedFiles(repository)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(files, "|") != "dir/new file.txt|keep.txt" {
		t.Errorf("staged files = %q", files)
	}

	snapshot, cleanup, err := StageSnapshot(repository, files)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cleanup() }()
	data, err := os.ReadFile(filepath.Join(snapshot, "keep.txt"))
	if err != nil || string(data) != "staged change" {
		t.Errorf("snapshot keep.txt = %q, %v: it must hold the staged content, not the working tree", data, err)
	}
	if _, err := os.Stat(filepath.Join(snapshot, "dir", "new file.txt")); err != nil {
		t.Errorf("snapshot lacks the new file: %v", err)
	}
	for _, name := range []string{"untracked.txt", "gone.txt"} {
		if _, err := os.Stat(filepath.Join(snapshot, name)); err == nil {
			t.Errorf("snapshot contains %s", name)
		}
	}
}

func TestStageSnapshotWithNoFiles(t *testing.T) {
	repository := newRepository(t)
	snapshot, cleanup, err := StageSnapshot(repository, nil)
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(snapshot); err != nil || !info.IsDir() {
		t.Errorf("snapshot = %v, %v", info, err)
	}
	if err := cleanup(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := StageSnapshot(repository, []string{"not-staged.txt"}); err == nil {
		t.Error("expected an error for a file that is not in the index")
	}
}
