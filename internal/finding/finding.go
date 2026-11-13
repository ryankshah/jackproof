package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

var severityRank = map[Severity]int{
	SeverityInfo:     0,
	SeverityLow:      1,
	SeverityMedium:   2,
	SeverityHigh:     3,
	SeverityCritical: 4,
}

func ParseSeverity(value string) (Severity, error) {
	severity := Severity(strings.ToLower(value))
	if _, ok := severityRank[severity]; !ok {
		return "", fmt.Errorf("unknown severity %q: want critical, high, medium, low or info", value)
	}
	return severity, nil
}

func (s Severity) Valid() bool {
	_, ok := severityRank[s]
	return ok
}

func (s Severity) AtLeast(floor Severity) bool {
	return severityRank[s] >= severityRank[floor]
}

type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

var confidenceRank = map[Confidence]int{
	ConfidenceLow:    0,
	ConfidenceMedium: 1,
	ConfidenceHigh:   2,
}

func ParseConfidence(value string) (Confidence, error) {
	confidence := Confidence(strings.ToLower(value))
	if _, ok := confidenceRank[confidence]; !ok {
		return "", fmt.Errorf("unknown confidence %q: want high, medium or low", value)
	}
	return confidence, nil
}

func (c Confidence) Valid() bool {
	_, ok := confidenceRank[c]
	return ok
}

func (c Confidence) AtLeast(floor Confidence) bool {
	return confidenceRank[c] >= confidenceRank[floor]
}

type Module string

const (
	ModuleScan     Module = "scan"
	ModulePosture  Module = "posture"
	ModuleHunt     Module = "hunt"
	ModuleExposure Module = "exposure"
)

func (m Module) Valid() bool {
	switch m {
	case ModuleScan, ModulePosture, ModuleHunt, ModuleExposure:
		return true
	}
	return false
}

type Method string

const (
	MethodPattern          Method = "pattern"
	MethodAST              Method = "ast"
	MethodIaCParse         Method = "iac-parse"
	MethodPolicyEval       Method = "policy-eval"
	MethodLogCorrelation   Method = "log-correlation"
	MethodFingerprintMatch Method = "fingerprint-match"
)

func (m Method) Valid() bool {
	switch m {
	case MethodPattern, MethodAST, MethodIaCParse, MethodPolicyEval, MethodLogCorrelation, MethodFingerprintMatch:
		return true
	}
	return false
}

type Flag string

const (
	FlagInferred       Flag = "inferred"
	FlagConfigImplied  Flag = "config-implied"
	FlagIncomplete     Flag = "incomplete"
	FlagUnverifiedRule Flag = "unverified-rule"
)

func (f Flag) Valid() bool {
	switch f {
	case FlagInferred, FlagConfigImplied, FlagIncomplete, FlagUnverifiedRule:
		return true
	}
	return false
}

type Evidence struct {
	Path      string    `json:"path,omitempty"`
	StartLine int       `json:"start_line,omitempty"`
	EndLine   int       `json:"end_line,omitempty"`
	Record    string    `json:"record,omitempty"`
	Timestamp time.Time `json:"timestamp,omitzero"`
	Excerpt   string    `json:"excerpt,omitempty"`
}

func (e Evidence) Location() string {
	if e.Path != "" {
		return fmt.Sprintf("%s:%d", e.Path, e.StartLine)
	}
	return e.Record
}

func (e Evidence) Validate() error {
	hasFile := e.Path != ""
	hasRecord := e.Record != ""
	switch {
	case hasFile == hasRecord:
		return errors.New("evidence needs exactly one of path or record")
	case hasFile && e.StartLine < 1:
		return errors.New("file evidence needs a start line of at least 1")
	case hasFile && e.EndLine < e.StartLine:
		return errors.New("file evidence end line is before start line")
	case hasRecord && e.Timestamp.IsZero():
		return errors.New("record evidence needs a timestamp")
	}
	return nil
}

type Finding struct {
	ID          string     `json:"id"`
	Rule        string     `json:"rule"`
	Module      Module     `json:"module"`
	Title       string     `json:"title"`
	Severity    Severity   `json:"severity"`
	Confidence  Confidence `json:"confidence"`
	Evidence    []Evidence `json:"evidence"`
	Method      Method     `json:"method"`
	Flags       []Flag     `json:"flags,omitempty"`
	Unproven    []string   `json:"unproven,omitempty"`
	Remediation string     `json:"remediation"`
	Refs        []string   `json:"refs,omitempty"`
}

const idLength = 12

func NewID(rule string, primary Evidence) string {
	sum := sha256.Sum256([]byte(rule + "\x00" + primary.Location()))
	return hex.EncodeToString(sum[:])[:idLength]
}

func (f Finding) Validate() error {
	switch {
	case f.ID == "":
		return errors.New("finding has no id")
	case f.Rule == "":
		return errors.New("finding has no rule")
	case !f.Module.Valid():
		return fmt.Errorf("finding has invalid module %q", f.Module)
	case f.Title == "":
		return errors.New("finding has no title")
	case !f.Severity.Valid():
		return fmt.Errorf("finding has invalid severity %q", f.Severity)
	case !f.Confidence.Valid():
		return fmt.Errorf("finding has invalid confidence %q", f.Confidence)
	case !f.Method.Valid():
		return fmt.Errorf("finding has invalid method %q", f.Method)
	case len(f.Evidence) == 0:
		return errors.New("finding has no evidence")
	case f.Remediation == "":
		return errors.New("finding has no remediation")
	}
	for _, flag := range f.Flags {
		if !flag.Valid() {
			return fmt.Errorf("finding has invalid flag %q", flag)
		}
	}
	for i, evidence := range f.Evidence {
		if err := evidence.Validate(); err != nil {
			return fmt.Errorf("evidence %d: %w", i, err)
		}
	}
	if want := NewID(f.Rule, f.Evidence[0]); f.ID != want {
		return fmt.Errorf("finding id %q does not match rule and primary evidence, want %q", f.ID, want)
	}
	return nil
}

type Filter struct {
	MinSeverity   Severity
	MinConfidence Confidence
}

func (flt Filter) Keep(f Finding) bool {
	if flt.MinSeverity != "" && !f.Severity.AtLeast(flt.MinSeverity) {
		return false
	}
	if flt.MinConfidence != "" && !f.Confidence.AtLeast(flt.MinConfidence) {
		return false
	}
	return true
}

func (flt Filter) Apply(findings []Finding) []Finding {
	kept := make([]Finding, 0, len(findings))
	for _, f := range findings {
		if flt.Keep(f) {
			kept = append(kept, f)
		}
	}
	return kept
}

func Sort(findings []Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.Severity != b.Severity {
			return severityRank[a.Severity] > severityRank[b.Severity]
		}
		if a.Confidence != b.Confidence {
			return confidenceRank[a.Confidence] > confidenceRank[b.Confidence]
		}
		if a.Rule != b.Rule {
			return a.Rule < b.Rule
		}
		return a.ID < b.ID
	})
}

func HighestSeverity(findings []Finding) (Severity, bool) {
	var highest Severity
	found := false
	for _, f := range findings {
		if !found || severityRank[f.Severity] > severityRank[highest] {
			highest = f.Severity
			found = true
		}
	}
	return highest, found
}
