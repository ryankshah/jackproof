package secret

import (
	"strings"
	"testing"
)

func TestRedact(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{"empty", "", "[redacted]"},
		{"short", "abc123", "[redacted]"},
		{"seven", "abcdefg", "[redacted]"},
		{"eight", "abcdefgh", "ab...gh"},
		{"twelve", "abcdefghijkl", "abc...jkl"},
		{"sixteen", "abcdefghijklmnop", "abcd...mnop"},
		{"long", "abcd" + strings.Repeat("m", 80) + "wxyz", "abcd...wxyz"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Redact(tt.value)
			if got != tt.want {
				t.Errorf("Redact(%q) = %q, want %q", tt.value, got, tt.want)
			}
			if len(tt.value) >= minRedactable && len(got) >= len(tt.value) {
				t.Errorf("redacted form %q is not shorter than input", got)
			}
		})
	}
}

func TestRedactNeverRevealsMoreThanHalf(t *testing.T) {
	for length := 0; length <= 100; length++ {
		value := strings.Repeat("k", length)
		got := Redact(value)
		revealed := strings.Count(got, "k")
		if revealed*2 > length {
			t.Errorf("length %d: %d characters revealed", length, revealed)
		}
	}
}

func TestFingerprint(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		wantFull  string
		wantShort string
	}{
		{
			name:      "empty",
			value:     "",
			wantFull:  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			wantShort: "e3b0c44298fc1c14",
		},
		{
			name:      "abc",
			value:     "abc",
			wantFull:  "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
			wantShort: "ba7816bf8f01cfea",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FullFingerprint(tt.value); got != tt.wantFull {
				t.Errorf("FullFingerprint = %q, want %q", got, tt.wantFull)
			}
			if got := Fingerprint(tt.value); got != tt.wantShort {
				t.Errorf("Fingerprint = %q, want %q", got, tt.wantShort)
			}
		})
	}
}

func TestNormalizeFingerprint(t *testing.T) {
	full := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"short", "ba7816bf8f01cfea", "ba7816bf8f01cfea", false},
		{"full", full, "ba7816bf8f01cfea", false},
		{"uppercase", strings.ToUpper(full), "ba7816bf8f01cfea", false},
		{"padded", "  ba7816bf8f01cfea\n", "ba7816bf8f01cfea", false},
		{"wrong length", "ba7816bf", "", true},
		{"not hex", "zz7816bf8f01cfea", "", true},
		{"empty", "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeFingerprint(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
