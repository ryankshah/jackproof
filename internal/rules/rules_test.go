package rules

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/ryankshah/jackproof/internal/finding"
)

const validRule = `id: JP-KEY-900
title: Example
severity: low
verified: true
matcher: example
description: Describes the rule.
remediation: Fix it.
refs:
  - https://example.com/docs
`

func ruleFS(files map[string]string) fstest.MapFS {
	fsys := fstest.MapFS{}
	for name, content := range files {
		fsys[name] = &fstest.MapFile{Data: []byte(content)}
	}
	return fsys
}

func TestLoadEmbedded(t *testing.T) {
	catalogue, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	rule, ok := catalogue.Get("JP-KEY-001")
	if !ok {
		t.Fatal("JP-KEY-001 is missing")
	}
	if rule.Module() != finding.ModuleScan {
		t.Errorf("module = %s, want scan", rule.Module())
	}
	if len(catalogue.All()) == 0 {
		t.Error("catalogue is empty")
	}
}

func TestEmbeddedRulesAreWellFormed(t *testing.T) {
	catalogue, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	for _, rule := range catalogue.All() {
		t.Run(rule.ID, func(t *testing.T) {
			if len(rule.Refs) == 0 {
				t.Error("rule has no references")
			}
			for _, banned := range []string{"!", "2014", "simply", "robust", "powerful", "seamless", "leverage", "comprehensive"} {
				for _, text := range []string{rule.Title, rule.Description, rule.Remediation} {
					if strings.Contains(strings.ToLower(text), banned) {
						t.Errorf("text contains banned content %q", banned)
					}
				}
			}
		})
	}
}

func TestLoad(t *testing.T) {
	tests := []struct {
		name    string
		files   map[string]string
		wantErr string
	}{
		{"valid", map[string]string{"JP-KEY-900.yaml": validRule}, ""},
		{"ignores non yaml", map[string]string{"JP-KEY-900.yaml": validRule, "notes.txt": "x"}, ""},
		{"pattern rule", map[string]string{"JP-KEY-900.yaml": strings.Replace(validRule, "matcher: example", "pattern: 'abc+'", 1)}, ""},
		{"bad id", map[string]string{"JP-BAD-1.yaml": strings.Replace(validRule, "JP-KEY-900", "JP-BAD-1", 1)}, "does not match"},
		{"file name mismatch", map[string]string{"other.yaml": validRule}, "file name must be"},
		{"missing title", map[string]string{"JP-KEY-900.yaml": strings.Replace(validRule, "title: Example\n", "", 1)}, "title is required"},
		{"bad severity", map[string]string{"JP-KEY-900.yaml": strings.Replace(validRule, "severity: low", "severity: severe", 1)}, "severity"},
		{"missing remediation", map[string]string{"JP-KEY-900.yaml": strings.Replace(validRule, "remediation: Fix it.\n", "", 1)}, "remediation is required"},
		{"both pattern and matcher", map[string]string{"JP-KEY-900.yaml": validRule + "pattern: 'a'\n"}, "exactly one"},
		{"neither pattern nor matcher", map[string]string{"JP-KEY-900.yaml": strings.Replace(validRule, "matcher: example\n", "", 1)}, "exactly one"},
		{"bad regex", map[string]string{"JP-KEY-900.yaml": strings.Replace(validRule, "matcher: example", "pattern: '('", 1)}, "pattern"},
		{"insecure ref", map[string]string{"JP-KEY-900.yaml": strings.Replace(validRule, "https://example.com/docs", "http://example.com/docs", 1)}, "https"},
		{"unknown field", map[string]string{"JP-KEY-900.yaml": validRule + "bogus: 1\n"}, "parse rule"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(ruleFS(tt.files))
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tt.wantErr != "" && err == nil:
				t.Fatalf("expected error containing %q", tt.wantErr)
			case tt.wantErr != "" && !strings.Contains(err.Error(), tt.wantErr):
				t.Fatalf("error %q does not contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestMerge(t *testing.T) {
	base, err := Load(ruleFS(map[string]string{"JP-KEY-900.yaml": validRule}))
	if err != nil {
		t.Fatal(err)
	}
	other := strings.Replace(validRule, "JP-KEY-900", "JP-KEY-901", 1)
	extra, err := Load(ruleFS(map[string]string{"JP-KEY-901.yaml": other}))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		extra     *Catalogue
		wantCount int
		wantErr   bool
	}{
		{"disjoint", extra, 2, false},
		{"duplicate", base, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			merged, err := base.Merge(tt.extra)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && len(merged.All()) != tt.wantCount {
				t.Errorf("merged has %d rules, want %d", len(merged.All()), tt.wantCount)
			}
		})
	}
	if len(base.All()) != 1 {
		t.Error("merge modified the receiver")
	}
}

func TestAllIsSortedAndUnverifiedFilters(t *testing.T) {
	second := strings.Replace(strings.Replace(validRule, "JP-KEY-900", "JP-POS-001", 1), "verified: true", "verified: false", 1)
	catalogue, err := Load(ruleFS(map[string]string{
		"JP-POS-001.yaml": second,
		"JP-KEY-900.yaml": validRule,
	}))
	if err != nil {
		t.Fatal(err)
	}
	all := catalogue.All()
	if all[0].ID != "JP-KEY-900" || all[1].ID != "JP-POS-001" {
		t.Errorf("order = %s, %s", all[0].ID, all[1].ID)
	}
	unverified := catalogue.Unverified()
	if len(unverified) != 1 || unverified[0].ID != "JP-POS-001" {
		t.Errorf("unverified = %+v", unverified)
	}
	if unverified[0].Module() != finding.ModulePosture {
		t.Errorf("module = %s, want posture", unverified[0].Module())
	}
}

func TestNewFinding(t *testing.T) {
	catalogue, err := Load(ruleFS(map[string]string{
		"JP-KEY-900.yaml": validRule,
		"JP-KEY-901.yaml": strings.Replace(strings.Replace(validRule, "JP-KEY-900", "JP-KEY-901", 1), "verified: true", "verified: false", 1),
	}))
	if err != nil {
		t.Fatal(err)
	}
	evidence := finding.Evidence{Path: "a.env", StartLine: 2, EndLine: 2, Excerpt: "KEY=abcd...wxyz"}

	tests := []struct {
		ruleID   string
		wantFlag bool
	}{
		{"JP-KEY-900", false},
		{"JP-KEY-901", true},
	}
	for _, tt := range tests {
		t.Run(tt.ruleID, func(t *testing.T) {
			rule, _ := catalogue.Get(tt.ruleID)
			f := rule.NewFinding(finding.MethodPattern, finding.ConfidenceHigh, evidence)
			if err := f.Validate(); err != nil {
				t.Fatalf("finding is invalid: %v", err)
			}
			hasFlag := len(f.Flags) == 1 && f.Flags[0] == finding.FlagUnverifiedRule
			if hasFlag != tt.wantFlag {
				t.Errorf("unverified flag = %v, want %v", hasFlag, tt.wantFlag)
			}
		})
	}
}

func TestRegexp(t *testing.T) {
	catalogue, err := Load(ruleFS(map[string]string{
		"JP-KEY-900.yaml": strings.Replace(validRule, "matcher: example", "pattern: 'ab+c'", 1),
	}))
	if err != nil {
		t.Fatal(err)
	}
	rule, _ := catalogue.Get("JP-KEY-900")
	tests := []struct {
		input string
		want  bool
	}{
		{"abbbc", true},
		{"ac", false},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := rule.Regexp().MatchString(tt.input); got != tt.want {
				t.Errorf("match = %v, want %v", got, tt.want)
			}
		})
	}
}
