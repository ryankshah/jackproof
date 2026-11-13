package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/ryankshah/jackproof/internal/finding"
	"github.com/ryankshah/jackproof/internal/graph"
	"github.com/ryankshah/jackproof/internal/rules"
)

const (
	maxListedSkips = 20
	noFindingsNote = "An empty result does not show the target is safe. Read the coverage section for what was and was not examined."
	toolName       = "jackproof"
)

type Report struct {
	Title     string
	Version   string
	Findings  []finding.Finding
	Coverage  finding.Coverage
	Graph     *graph.Graph
	Rules     *rules.Catalogue
	Providers map[string]string
}

type printer struct {
	w   io.Writer
	err error
}

func (p *printer) printf(format string, args ...any) {
	if p.err == nil {
		_, p.err = fmt.Fprintf(p.w, format, args...)
	}
}

var severityOrder = []finding.Severity{
	finding.SeverityCritical, finding.SeverityHigh, finding.SeverityMedium, finding.SeverityLow, finding.SeverityInfo,
}

func summary(findings []finding.Finding) string {
	if len(findings) == 0 {
		return "No findings"
	}
	counts := make(map[finding.Severity]int)
	for _, f := range findings {
		counts[f.Severity]++
	}
	var parts []string
	for _, severity := range severityOrder {
		if counts[severity] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[severity], severity))
		}
	}
	noun := "findings"
	if len(findings) == 1 {
		noun = "finding"
	}
	return fmt.Sprintf("%d %s: %s", len(findings), noun, strings.Join(parts, ", "))
}

func location(e finding.Evidence) string {
	if e.Path != "" {
		if e.EndLine > e.StartLine {
			return fmt.Sprintf("%s:%d-%d", e.Path, e.StartLine, e.EndLine)
		}
		return fmt.Sprintf("%s:%d", e.Path, e.StartLine)
	}
	return fmt.Sprintf("%s at %s", e.Record, e.Timestamp.UTC().Format("2006-01-02T15:04:05Z"))
}

type holderLine struct {
	holder   graph.Holder
	delivery graph.Delivery
	line     graph.Location
}

func credentialHolders(g *graph.Graph, key string) []holderLine {
	var lines []holderLine
	seen := make(map[string]bool)
	for _, edge := range g.EdgesOf(key) {
		holder, _ := g.Holder(edge.Holder)
		id := holder.ID + "|" + string(edge.Delivery)
		if seen[id] {
			continue
		}
		seen[id] = true
		lines = append(lines, holderLine{holder: holder, delivery: edge.Delivery, line: edge.Location})
	}
	return lines
}

func credentialLabel(c graph.Credential) string {
	if c.Kind == graph.KindLiteral {
		return fmt.Sprintf("%s (literal key)", c.Redacted)
	}
	return fmt.Sprintf("%s (reference)", c.Name)
}

func holderLabel(h graph.Holder) string {
	label := fmt.Sprintf("%s %s", h.Kind, h.Name)
	if h.Environment != "" {
		label += fmt.Sprintf(" [%s]", h.Environment)
	}
	if h.Untrusted {
		label += " (may run untrusted code)"
	}
	return label
}

func splitUnverified(entries []string) (ruleIDs []string, formats, clients int) {
	for _, entry := range entries {
		switch {
		case strings.HasPrefix(entry, "format:"):
			formats++
		case strings.HasPrefix(entry, "client:"):
			clients++
		default:
			ruleIDs = append(ruleIDs, entry)
		}
	}
	sort.Strings(ruleIDs)
	return ruleIDs, formats, clients
}

func kindSummary(c finding.Coverage) string {
	kinds := c.Kinds()
	parts := make([]string, len(kinds))
	for i, kind := range kinds {
		parts[i] = fmt.Sprintf("%s %d", kind, c.FilesScanned[kind])
	}
	return strings.Join(parts, ", ")
}

var formats = []string{"text", "json", "sarif", "md"}

func Formats() []string {
	return append([]string(nil), formats...)
}

func Write(w io.Writer, format string, r Report) error {
	switch format {
	case "text":
		return WriteText(w, r)
	case "json":
		return WriteJSON(w, r)
	case "sarif":
		return WriteSARIF(w, r)
	case "md", "markdown":
		return WriteMarkdown(w, r)
	}
	return fmt.Errorf("unknown format %q: want %s", format, strings.Join(formats, ", "))
}
