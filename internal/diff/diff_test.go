package diff

import (
	"testing"
	"time"

	"github.com/ryankshah/jackproof/internal/finding"
)

func newFinding(rule, path, title string, line int, severity finding.Severity, confidence finding.Confidence) finding.Finding {
	evidence := finding.Evidence{Path: path, StartLine: line, EndLine: line}
	return finding.Finding{
		ID: finding.NewID(rule, evidence), Rule: rule, Title: title, Severity: severity, Confidence: confidence,
		Evidence: []finding.Evidence{evidence},
	}
}

func TestCompare(t *testing.T) {
	high, medium := finding.SeverityHigh, finding.SeverityMedium
	confident, unsure := finding.ConfidenceHigh, finding.ConfidenceMedium
	tests := []struct {
		name                                          string
		base, head                                    []finding.Finding
		wantAdded, wantRemoved, wantChanged, wantSame int
	}{
		{"nothing", nil, nil, 0, 0, 0, 0},
		{"added", nil, []finding.Finding{newFinding("JP-KEY-001", ".env", "key", 1, high, confident)}, 1, 0, 0, 0},
		{"removed", []finding.Finding{newFinding("JP-KEY-001", ".env", "key", 1, high, confident)}, nil, 0, 1, 0, 0},
		{
			"same finding on a different line is unchanged",
			[]finding.Finding{newFinding("JP-KEY-001", ".env", "key", 1, high, confident)},
			[]finding.Finding{newFinding("JP-KEY-001", ".env", "key", 9, high, confident)},
			0, 0, 0, 1,
		},
		{
			"severity change",
			[]finding.Finding{newFinding("JP-KEY-001", ".env", "key", 1, medium, confident)},
			[]finding.Finding{newFinding("JP-KEY-001", ".env", "key", 1, high, confident)},
			0, 0, 1, 0,
		},
		{
			"confidence change",
			[]finding.Finding{newFinding("JP-KEY-001", ".env", "key", 1, high, confident)},
			[]finding.Finding{newFinding("JP-KEY-001", ".env", "key", 1, high, unsure)},
			0, 0, 1, 0,
		},
		{
			"different file is a new finding",
			[]finding.Finding{newFinding("JP-KEY-001", "a.env", "key", 1, high, confident)},
			[]finding.Finding{newFinding("JP-KEY-001", "b.env", "key", 1, high, confident)},
			1, 1, 0, 0,
		},
		{
			"duplicates are matched one to one",
			[]finding.Finding{newFinding("JP-KEY-001", ".env", "key", 1, high, confident)},
			[]finding.Finding{newFinding("JP-KEY-001", ".env", "key", 1, high, confident), newFinding("JP-KEY-001", ".env", "key", 2, high, confident)},
			1, 0, 0, 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Compare(tt.base, tt.head)
			if len(result.Added) != tt.wantAdded || len(result.Removed) != tt.wantRemoved || len(result.Changed) != tt.wantChanged || result.Unchanged != tt.wantSame {
				t.Errorf("got added %d removed %d changed %d unchanged %d, want %d %d %d %d",
					len(result.Added), len(result.Removed), len(result.Changed), result.Unchanged,
					tt.wantAdded, tt.wantRemoved, tt.wantChanged, tt.wantSame)
			}
		})
	}
}

func TestCompareUsesRecordForLogFindings(t *testing.T) {
	evidence := finding.Evidence{Record: "evt-1", Timestamp: time.Unix(1, 0)}
	a := finding.Finding{Rule: "JP-HUNT-001", Title: "t", Severity: finding.SeverityHigh, Confidence: finding.ConfidenceHigh, Evidence: []finding.Evidence{evidence}}
	other := a
	other.Evidence = []finding.Evidence{{Record: "evt-2", Timestamp: time.Unix(2, 0)}}
	result := Compare([]finding.Finding{a}, []finding.Finding{other})
	if len(result.Added) != 1 || len(result.Removed) != 1 {
		t.Errorf("result = %+v", result)
	}
}

func TestCompareSortsBySeverity(t *testing.T) {
	result := Compare(nil, []finding.Finding{
		newFinding("JP-KEY-020", "a", "x", 1, finding.SeverityMedium, finding.ConfidenceHigh),
		newFinding("JP-KEY-001", "b", "y", 1, finding.SeverityHigh, finding.ConfidenceHigh),
	})
	if result.Added[0].Rule != "JP-KEY-001" {
		t.Errorf("added = %+v", result.Added)
	}
}
