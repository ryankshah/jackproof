package main

import (
	"bytes"
	"errors"
	"testing"
)

func TestRun(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantUsage  bool
		wantStdout string
	}{
		{name: "no arguments", args: nil, wantUsage: true},
		{name: "version", args: []string{"version"}, wantStdout: "dev\n"},
		{name: "unknown command", args: []string{"nope"}, wantUsage: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout bytes.Buffer
			err := run(tt.args, &stdout)
			if errors.Is(err, errUsage) != tt.wantUsage {
				t.Errorf("usage error = %v, want %v (err: %v)", errors.Is(err, errUsage), tt.wantUsage, err)
			}
			if stdout.String() != tt.wantStdout {
				t.Errorf("stdout = %q, want %q", stdout.String(), tt.wantStdout)
			}
		})
	}
}
