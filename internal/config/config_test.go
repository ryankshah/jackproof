package config

import (
	"os"
	"path/filepath"
	"testing"
)

const sample = `ignore:
  paths:
    - "vendor/**"
    - "**/*.min.js"
    - docs/internal.md
  rules:
    - JP-KEY-030
environments:
  prod:
    - "deploy/prod/**"
    - "**/prod.env"
  dev:
    - "deploy/dev/**"
`

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"full", sample, false},
		{"empty", "", false},
		{"unknown field", "bogus: true\n", true},
		{"invalid yaml", "ignore: [", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.input))
			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestIgnoresPath(t *testing.T) {
	cfg, err := Parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		path string
		want bool
	}{
		{"vendor/lib/a.go", true},
		{"vendor", false},
		{"app/vendor/a.go", false},
		{"web/static/app.min.js", true},
		{"app.min.js", true},
		{"web/app.js", false},
		{"docs/internal.md", true},
		{"docs/other.md", false},
		{`vendor\lib\a.go`, true},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := cfg.IgnoresPath(tt.path); got != tt.want {
				t.Errorf("IgnoresPath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestIgnoresRule(t *testing.T) {
	cfg, err := Parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.IgnoresRule("JP-KEY-030") {
		t.Error("JP-KEY-030 should be ignored")
	}
	if cfg.IgnoresRule("JP-KEY-001") {
		t.Error("JP-KEY-001 should not be ignored")
	}
}

func TestEnvironmentForPath(t *testing.T) {
	cfg, err := Parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		path string
		want string
	}{
		{"deploy/prod/app.yaml", "prod"},
		{"deploy/prod/nested/app.yaml", "prod"},
		{"config/prod.env", "prod"},
		{"prod.env", "prod"},
		{"deploy/dev/app.yaml", "dev"},
		{"deploy/staging/app.yaml", ""},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := cfg.EnvironmentForPath(tt.path); got != tt.want {
				t.Errorf("EnvironmentForPath(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestLoadIfPresent(t *testing.T) {
	withFile := t.TempDir()
	if err := os.WriteFile(filepath.Join(withFile, FileName), []byte(sample), 0o600); err != nil {
		t.Fatal(err)
	}
	withoutFile := t.TempDir()
	withBadFile := t.TempDir()
	if err := os.WriteFile(filepath.Join(withBadFile, FileName), []byte("bogus: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name         string
		dir          string
		wantErr      bool
		wantIgnoring bool
	}{
		{"present", withFile, false, true},
		{"absent", withoutFile, false, false},
		{"invalid", withBadFile, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := LoadIfPresent(tt.dir)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && cfg.IgnoresPath("vendor/a.go") != tt.wantIgnoring {
				t.Errorf("ignoring = %v, want %v", !tt.wantIgnoring, tt.wantIgnoring)
			}
		})
	}
}
