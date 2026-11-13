package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ryankshah/jackproof/internal/finding"
	"github.com/ryankshah/jackproof/internal/graph"
	"github.com/ryankshah/jackproof/internal/rules"
)

func sampleFindings() []finding.Finding {
	first := finding.Evidence{Path: "deploy/.env", StartLine: 3, EndLine: 3, Excerpt: "OPENAI_API_KEY=sk-b...bbbb"}
	second := finding.Evidence{Path: "deploy/compose.yaml", StartLine: 9, EndLine: 11, Excerpt: "api | worker"}
	logged := finding.Evidence{Record: "evt-1", Timestamp: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)}
	return []finding.Finding{
		{
			ID: finding.NewID("JP-KEY-001", first), Rule: "JP-KEY-001", Module: finding.ModuleScan,
			Title: "OpenAI key sk-b...bbbb committed in deploy/.env", Severity: finding.SeverityHigh, Confidence: finding.ConfidenceHigh,
			Evidence: []finding.Evidence{first, second}, Method: finding.MethodPattern,
			Flags:       []finding.Flag{finding.FlagUnverifiedRule},
			Unproven:    []string{"Whether the key is still active."},
			Remediation: "Revoke the key.",
			Refs:        []string{"https://example.com/docs"},
		},
		{
			ID: finding.NewID("JP-HUNT-001", logged), Rule: "JP-HUNT-001", Module: finding.ModuleHunt,
			Title: "Model enabled then invoked", Severity: finding.SeverityMedium, Confidence: finding.ConfidenceMedium,
			Evidence: []finding.Evidence{logged}, Method: finding.MethodLogCorrelation,
			Remediation: "Review the principal.",
		},
	}
}

func sampleGraph() *graph.Graph {
	g := graph.New()
	g.AddCredential(graph.Credential{
		Key: "literal:aaaa", Kind: graph.KindLiteral, Provider: "openai", Redacted: "sk-b...bbbb",
		Reach: "Model inference billed to the owner.", Definitions: []graph.Location{{Path: "deploy/.env", Line: 3}},
	})
	holder := g.AddHolder(graph.Holder{Kind: graph.HolderComposeService, Name: "api", Location: graph.Location{Path: "deploy/compose.yaml", Line: 9}, Environment: "prod", Untrusted: true})
	g.AddEdge(graph.Edge{Credential: "literal:aaaa", Holder: holder, Delivery: graph.DeliveryEnvFile, Location: graph.Location{Path: "deploy/compose.yaml", Line: 12}})
	return g
}

func sampleReport() Report {
	return Report{
		Title:     "jackproof scan",
		Version:   "1.2.3",
		Findings:  sampleFindings(),
		Graph:     sampleGraph(),
		Providers: map[string]string{"openai": "OpenAI"},
		Coverage: finding.Coverage{
			FilesScanned:    map[string]int{"go": 2, "yaml": 1},
			FilesSkipped:    []finding.Skip{{Path: "vendor/", Reason: "third-party dependencies"}},
			LogSources:      []string{"cloudtrail: events.json"},
			TimeRanges:      []finding.TimeRange{{Source: "events.json", From: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), To: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)}},
			UnverifiedRules: []string{"JP-KEY-001", "format:openai/legacy-key", "format:groq/api-key", "client:python/openai"},
		},
	}
}

type writer func(*bytes.Buffer, Report) error

func writers() map[string]writer {
	return map[string]writer{
		"text":     func(b *bytes.Buffer, r Report) error { return WriteText(b, r) },
		"markdown": func(b *bytes.Buffer, r Report) error { return WriteMarkdown(b, r) },
		"json":     func(b *bytes.Buffer, r Report) error { return WriteJSON(b, r) },
		"sarif":    func(b *bytes.Buffer, r Report) error { return WriteSARIF(b, r) },
	}
}

func TestEveryFormatIncludesCoverageAndEmptyNote(t *testing.T) {
	empty := Report{Title: "jackproof scan", Coverage: finding.Coverage{FilesScanned: map[string]int{"go": 1}}}
	for name, write := range writers() {
		t.Run(name, func(t *testing.T) {
			var full, none bytes.Buffer
			if err := write(&full, sampleReport()); err != nil {
				t.Fatal(err)
			}
			if err := write(&none, empty); err != nil {
				t.Fatal(err)
			}
			if name == "sarif" {
				return
			}
			if !strings.Contains(full.String(), "third-party dependencies") {
				t.Errorf("%s output lacks skipped files", name)
			}
			if !strings.Contains(full.String(), "JP-KEY-001") {
				t.Errorf("%s output lacks the unverified rule", name)
			}
			if name == "json" {
				return
			}
			if !strings.Contains(none.String(), "does not show the target is safe") {
				t.Errorf("%s empty output lacks the safety note", name)
			}
		})
	}
}

func TestTextContent(t *testing.T) {
	var out bytes.Buffer
	if err := WriteText(&out, sampleReport()); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{
		"jackproof scan: 2 findings: 1 high, 1 medium",
		"HIGH     JP-KEY-001",
		"deploy/.env:3",
		"deploy/compose.yaml:9-11",
		"evt-1 at 2026-01-02T03:04:05Z",
		"flags: unverified-rule",
		"not established: Whether the key is still active.",
		"Credential graph",
		"OpenAI sk-b...bbbb (literal key)",
		"held by compose-service api [prod] (may run untrusted code) via env-file",
		"environments: prod",
		"if a holder is compromised: Model inference billed to the owner.",
		"files scanned: 3 (go 2, yaml 1)",
		"provider key formats not verified: 2, SDK client patterns not verified: 1",
		"time range for events.json: 2026-01-01T00:00:00Z to 2026-01-02T00:00:00Z",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("text output lacks %q\n%s", want, text)
		}
	}
}

func TestMarkdownContent(t *testing.T) {
	var out bytes.Buffer
	if err := WriteMarkdown(&out, sampleReport()); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{
		"# jackproof scan",
		"| high | high | JP-KEY-001 |",
		"### HIGH JP-KEY-001:",
		"- Finding id: `",
		"```text",
		"- https://example.com/docs",
		"## Credential graph",
		"## Coverage",
		"- Files skipped: 1",
		"`vendor/`: third-party dependencies",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("markdown output lacks %q\n%s", want, text)
		}
	}
	if strings.Contains(text, "| api | worker") {
		t.Error("table cells must escape pipe characters")
	}
}

func TestJSONContent(t *testing.T) {
	var out bytes.Buffer
	if err := WriteJSON(&out, sampleReport()); err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Schema   int `json:"schema"`
		Tool     string
		Version  string
		Findings []struct {
			ID       string
			Rule     string
			Evidence []struct {
				Path string
			}
		}
		Graph struct {
			Credentials []struct{ Key, Reach string }
			Holders     []struct{ ID string }
			Edges       []struct{ Credential, Holder string }
		}
		Coverage struct {
			FilesScanned map[string]int `json:"files_scanned"`
		}
	}
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if decoded.Schema != 1 || decoded.Tool != "jackproof" || decoded.Version != "1.2.3" {
		t.Errorf("header = %+v", decoded)
	}
	if len(decoded.Findings) != 2 || decoded.Findings[0].Rule != "JP-KEY-001" || decoded.Findings[0].Evidence[0].Path != "deploy/.env" {
		t.Errorf("findings = %+v", decoded.Findings)
	}
	if len(decoded.Graph.Credentials) != 1 || decoded.Graph.Credentials[0].Reach == "" || len(decoded.Graph.Edges) != 1 {
		t.Errorf("graph = %+v", decoded.Graph)
	}
	if decoded.Coverage.FilesScanned["go"] != 2 {
		t.Errorf("coverage = %+v", decoded.Coverage)
	}
}

func TestJSONEmptyFindingsIsAnArray(t *testing.T) {
	var out bytes.Buffer
	if err := WriteJSON(&out, Report{Title: "x"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"findings": []`) {
		t.Errorf("output = %s", out.String())
	}
}

func TestSARIFContent(t *testing.T) {
	ruleSet, err := rules.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	report := sampleReport()
	report.Rules = ruleSet
	var out bytes.Buffer
	if err := WriteSARIF(&out, report); err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Schema  string `json:"$schema"`
		Version string
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string
					Rules []struct {
						ID         string
						Help       struct{ Text string }
						Properties map[string]any
					}
				}
			}
			Results []struct {
				RuleID    string
				Level     string
				Message   struct{ Text string }
				Locations []struct {
					PhysicalLocation struct {
						Region struct{ StartLine, EndLine int }
					}
				}
				RelatedLocations    []struct{ ID int }
				PartialFingerprints map[string]string
			}
		}
	}
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if decoded.Version != "2.1.0" || !strings.Contains(decoded.Schema, "sarif") || len(decoded.Runs) != 1 {
		t.Fatalf("header = %+v", decoded)
	}
	run := decoded.Runs[0]
	if run.Tool.Driver.Name != "jackproof" || len(run.Tool.Driver.Rules) != 2 {
		t.Errorf("driver = %+v", run.Tool.Driver)
	}
	if run.Tool.Driver.Rules[0].ID != "JP-HUNT-001" || run.Tool.Driver.Rules[1].Properties["security-severity"] != "8.0" {
		t.Errorf("rules = %+v", run.Tool.Driver.Rules)
	}
	if len(run.Results) != 2 {
		t.Fatalf("results = %d", len(run.Results))
	}
	first := run.Results[0]
	if first.Level != "error" || len(first.Locations) != 1 || first.Locations[0].PhysicalLocation.Region.StartLine != 3 {
		t.Errorf("first result = %+v", first)
	}
	if len(first.RelatedLocations) != 1 || first.RelatedLocations[0].ID != 1 {
		t.Errorf("related = %+v", first.RelatedLocations)
	}
	if !strings.Contains(first.Message.Text, "Not established: Whether the key is still active.") {
		t.Errorf("message = %q", first.Message.Text)
	}
	if first.PartialFingerprints["jackproofFindingId/v1"] == "" {
		t.Error("missing partial fingerprint")
	}
	second := run.Results[1]
	if second.Level != "warning" || len(second.Locations) != 0 {
		t.Errorf("second result = %+v", second)
	}
}

func TestSarifLevel(t *testing.T) {
	tests := []struct {
		severity finding.Severity
		want     string
	}{
		{finding.SeverityCritical, "error"},
		{finding.SeverityHigh, "error"},
		{finding.SeverityMedium, "warning"},
		{finding.SeverityLow, "note"},
		{finding.SeverityInfo, "note"},
	}
	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			if got := sarifLevel(tt.severity); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSummary(t *testing.T) {
	high := finding.Finding{Severity: finding.SeverityHigh}
	low := finding.Finding{Severity: finding.SeverityLow}
	tests := []struct {
		name     string
		findings []finding.Finding
		want     string
	}{
		{"none", nil, "No findings"},
		{"one", []finding.Finding{high}, "1 finding: 1 high"},
		{"mixed", []finding.Finding{low, high, high}, "3 findings: 2 high, 1 low"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := summary(tt.findings); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestWritersReportErrors(t *testing.T) {
	report := sampleReport()
	tests := map[string]func() error{
		"text":     func() error { return WriteText(failingWriter{}, report) },
		"markdown": func() error { return WriteMarkdown(failingWriter{}, report) },
		"json":     func() error { return WriteJSON(failingWriter{}, report) },
		"sarif":    func() error { return WriteSARIF(failingWriter{}, report) },
	}
	for name, write := range tests {
		t.Run(name, func(t *testing.T) {
			if err := write(); err == nil {
				t.Error("expected the write error to propagate")
			}
		})
	}
}

func TestSkippedListIsCapped(t *testing.T) {
	var coverage finding.Coverage
	for i := 0; i < maxListedSkips+5; i++ {
		coverage.AddSkipped("f", "binary file")
	}
	var out bytes.Buffer
	if err := WriteText(&out, Report{Title: "t", Coverage: coverage}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "and 5 more") {
		t.Errorf("output = %s", out.String())
	}
}

func TestWriteDispatch(t *testing.T) {
	tests := []struct {
		format  string
		want    string
		wantErr bool
	}{
		{"text", "jackproof scan: 2 findings", false},
		{"json", `"schema": 1`, false},
		{"sarif", `"version": "2.1.0"`, false},
		{"md", "# jackproof scan", false},
		{"markdown", "# jackproof scan", false},
		{"pdf", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			var out bytes.Buffer
			err := Write(&out, tt.format, sampleReport())
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if !strings.Contains(out.String(), tt.want) {
				t.Errorf("output lacks %q", tt.want)
			}
		})
	}
	if len(Formats()) != 4 {
		t.Errorf("Formats = %v", Formats())
	}
}
