package finding

import (
	"testing"
	"time"
)

func validFinding() Finding {
	evidence := Evidence{Path: "deploy/app.yaml", StartLine: 10, EndLine: 12, Excerpt: "OPENAI_API_KEY=sk-p...xxxx"}
	return Finding{
		ID:          NewID("JP-KEY-001", evidence),
		Rule:        "JP-KEY-001",
		Module:      ModuleScan,
		Title:       "Provider key committed to repository",
		Severity:    SeverityHigh,
		Confidence:  ConfidenceHigh,
		Evidence:    []Evidence{evidence},
		Method:      MethodPattern,
		Remediation: "Rotate the key and remove it from history.",
	}
}

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		input   string
		want    Severity
		wantErr bool
	}{
		{input: "critical", want: SeverityCritical},
		{input: "HIGH", want: SeverityHigh},
		{input: "info", want: SeverityInfo},
		{input: "urgent", wantErr: true},
		{input: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseSeverity(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseConfidence(t *testing.T) {
	tests := []struct {
		input   string
		want    Confidence
		wantErr bool
	}{
		{input: "high", want: ConfidenceHigh},
		{input: "Medium", want: ConfidenceMedium},
		{input: "low", want: ConfidenceLow},
		{input: "certain", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseConfidence(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSeverityAtLeast(t *testing.T) {
	tests := []struct {
		severity Severity
		floor    Severity
		want     bool
	}{
		{SeverityCritical, SeverityHigh, true},
		{SeverityHigh, SeverityHigh, true},
		{SeverityMedium, SeverityHigh, false},
		{SeverityInfo, SeverityLow, false},
	}
	for _, tt := range tests {
		t.Run(string(tt.severity)+">="+string(tt.floor), func(t *testing.T) {
			if got := tt.severity.AtLeast(tt.floor); got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfidenceAtLeast(t *testing.T) {
	tests := []struct {
		confidence Confidence
		floor      Confidence
		want       bool
	}{
		{ConfidenceHigh, ConfidenceMedium, true},
		{ConfidenceMedium, ConfidenceMedium, true},
		{ConfidenceLow, ConfidenceMedium, false},
	}
	for _, tt := range tests {
		t.Run(string(tt.confidence)+">="+string(tt.floor), func(t *testing.T) {
			if got := tt.confidence.AtLeast(tt.floor); got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewID(t *testing.T) {
	a := Evidence{Path: "a.env", StartLine: 3, EndLine: 3}
	b := Evidence{Path: "a.env", StartLine: 4, EndLine: 4}
	logRecord := Evidence{Record: "evt-1", Timestamp: time.Unix(0, 0)}

	tests := []struct {
		name      string
		ruleA     string
		evidenceA Evidence
		ruleB     string
		evidenceB Evidence
		wantSame  bool
	}{
		{"same inputs", "JP-KEY-001", a, "JP-KEY-001", a, true},
		{"different line", "JP-KEY-001", a, "JP-KEY-001", b, false},
		{"different rule", "JP-KEY-001", a, "JP-KEY-010", a, false},
		{"log record", "JP-HUNT-001", logRecord, "JP-HUNT-001", logRecord, true},
		{"excerpt ignored", "JP-KEY-001", a, "JP-KEY-001", Evidence{Path: "a.env", StartLine: 3, EndLine: 9, Excerpt: "x"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idA := NewID(tt.ruleA, tt.evidenceA)
			idB := NewID(tt.ruleB, tt.evidenceB)
			if len(idA) != idLength {
				t.Errorf("id length = %d, want %d", len(idA), idLength)
			}
			if (idA == idB) != tt.wantSame {
				t.Errorf("ids %q and %q: same = %v, want %v", idA, idB, idA == idB, tt.wantSame)
			}
		})
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Finding)
		wantErr bool
	}{
		{name: "valid", mutate: func(*Finding) {}},
		{name: "missing id", mutate: func(f *Finding) { f.ID = "" }, wantErr: true},
		{name: "wrong id", mutate: func(f *Finding) { f.ID = "000000000000" }, wantErr: true},
		{name: "missing rule", mutate: func(f *Finding) { f.Rule = "" }, wantErr: true},
		{name: "bad module", mutate: func(f *Finding) { f.Module = "other" }, wantErr: true},
		{name: "missing title", mutate: func(f *Finding) { f.Title = "" }, wantErr: true},
		{name: "bad severity", mutate: func(f *Finding) { f.Severity = "severe" }, wantErr: true},
		{name: "bad confidence", mutate: func(f *Finding) { f.Confidence = "sure" }, wantErr: true},
		{name: "bad method", mutate: func(f *Finding) { f.Method = "guess" }, wantErr: true},
		{name: "bad flag", mutate: func(f *Finding) { f.Flags = []Flag{"odd"} }, wantErr: true},
		{name: "good flag", mutate: func(f *Finding) { f.Flags = []Flag{FlagInferred} }},
		{name: "no evidence", mutate: func(f *Finding) { f.Evidence = nil }, wantErr: true},
		{name: "evidence without location", mutate: func(f *Finding) { f.Evidence = []Evidence{{Excerpt: "x"}} }, wantErr: true},
		{name: "no remediation", mutate: func(f *Finding) { f.Remediation = "" }, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := validFinding()
			tt.mutate(&f)
			if err := f.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestEvidenceValidate(t *testing.T) {
	now := time.Unix(1700000000, 0)
	tests := []struct {
		name     string
		evidence Evidence
		wantErr  bool
	}{
		{"file", Evidence{Path: "a", StartLine: 1, EndLine: 1}, false},
		{"file range", Evidence{Path: "a", StartLine: 2, EndLine: 5}, false},
		{"file zero line", Evidence{Path: "a"}, true},
		{"file reversed range", Evidence{Path: "a", StartLine: 5, EndLine: 2}, true},
		{"record", Evidence{Record: "r1", Timestamp: now}, false},
		{"record without time", Evidence{Record: "r1"}, true},
		{"both", Evidence{Path: "a", StartLine: 1, EndLine: 1, Record: "r1", Timestamp: now}, true},
		{"neither", Evidence{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.evidence.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestFilterApply(t *testing.T) {
	build := func(severity Severity, confidence Confidence) Finding {
		f := validFinding()
		f.Severity = severity
		f.Confidence = confidence
		return f
	}
	findings := []Finding{
		build(SeverityCritical, ConfidenceHigh),
		build(SeverityMedium, ConfidenceLow),
		build(SeverityLow, ConfidenceMedium),
	}
	tests := []struct {
		name   string
		filter Filter
		want   int
	}{
		{"no filter", Filter{}, 3},
		{"severity high", Filter{MinSeverity: SeverityHigh}, 1},
		{"severity low", Filter{MinSeverity: SeverityLow}, 3},
		{"confidence medium", Filter{MinConfidence: ConfidenceMedium}, 2},
		{"both", Filter{MinSeverity: SeverityMedium, MinConfidence: ConfidenceMedium}, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := len(tt.filter.Apply(findings)); got != tt.want {
				t.Errorf("kept %d, want %d", got, tt.want)
			}
		})
	}
}

func TestSort(t *testing.T) {
	build := func(rule string, severity Severity, confidence Confidence) Finding {
		f := validFinding()
		f.Rule = rule
		f.Severity = severity
		f.Confidence = confidence
		return f
	}
	findings := []Finding{
		build("JP-KEY-020", SeverityMedium, ConfidenceHigh),
		build("JP-KEY-010", SeverityHigh, ConfidenceLow),
		build("JP-KEY-001", SeverityHigh, ConfidenceHigh),
		build("JP-KEY-002", SeverityHigh, ConfidenceHigh),
	}
	Sort(findings)
	want := []string{"JP-KEY-001", "JP-KEY-002", "JP-KEY-010", "JP-KEY-020"}
	for i, rule := range want {
		if findings[i].Rule != rule {
			t.Errorf("position %d = %s, want %s", i, findings[i].Rule, rule)
		}
	}
}

func TestHighestSeverity(t *testing.T) {
	low := validFinding()
	low.Severity = SeverityLow
	high := validFinding()
	high.Severity = SeverityHigh

	tests := []struct {
		name      string
		findings  []Finding
		want      Severity
		wantFound bool
	}{
		{"empty", nil, "", false},
		{"single", []Finding{low}, SeverityLow, true},
		{"mixed", []Finding{low, high}, SeverityHigh, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, found := HighestSeverity(tt.findings)
			if got != tt.want || found != tt.wantFound {
				t.Errorf("got %q, %v, want %q, %v", got, found, tt.want, tt.wantFound)
			}
		})
	}
}
