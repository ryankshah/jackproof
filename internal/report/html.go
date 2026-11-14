package report

import (
	_ "embed"
	"fmt"
	"html/template"
	"io"
	"strings"

	"github.com/ryankshah/jackproof/internal/finding"
)

//go:embed report.html.tmpl
var htmlTemplate string

type htmlFinding struct {
	finding.Finding
	Locations   []htmlEvidence
	FlagText    string
	Fix         []string
	SeverityTag string
}

type htmlEvidence struct {
	Where   string
	Excerpt string
}

type htmlCredential struct {
	Label        string
	Provider     string
	Definitions  []string
	Holders      []string
	Environments string
	Reach        string
}

type htmlPage struct {
	Title       string
	Version     string
	Summary     string
	Empty       bool
	EmptyNote   string
	Findings    []htmlFinding
	Credentials []htmlCredential
	Extras      []Extra
	Coverage    htmlCoverage
}

type htmlCoverage struct {
	Scanned      string
	Skipped      []finding.Skip
	SkippedMore  int
	SkippedTotal int
	LogSources   []string
	Ranges       []string
	Rules        []string
	Detail       string
}

func WriteHTML(w io.Writer, r Report) error {
	parsed, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("parse html template: %w", err)
	}
	if err := parsed.Execute(w, r.htmlPage()); err != nil {
		return fmt.Errorf("write html report: %w", err)
	}
	return nil
}

func (r Report) htmlPage() htmlPage {
	page := htmlPage{
		Title: r.Title, Version: r.Version, Summary: summary(r.Findings),
		Empty: len(r.Findings) == 0, EmptyNote: noFindingsNote, Extras: r.Extras,
	}
	for _, f := range r.Findings {
		entry := htmlFinding{Finding: f, FlagText: joinFlags(f.Flags), Fix: strings.Split(f.Remediation, "\n\n"), SeverityTag: string(f.Severity)}
		for _, evidence := range f.Evidence {
			entry.Locations = append(entry.Locations, htmlEvidence{Where: location(evidence), Excerpt: evidence.Excerpt})
		}
		page.Findings = append(page.Findings, entry)
	}
	if r.Graph != nil {
		for _, credential := range r.Graph.Credentials() {
			entry := htmlCredential{Label: credentialLabel(credential), Provider: r.providerName(credential.Provider), Reach: credential.Reach}
			for _, definition := range credential.Definitions {
				entry.Definitions = append(entry.Definitions, fmt.Sprintf("%s:%d", definition.Path, definition.Line))
			}
			for _, held := range credentialHolders(r.Graph, credential.Key) {
				entry.Holders = append(entry.Holders, fmt.Sprintf("%s via %s at %s:%d", holderLabel(held.holder), held.delivery, held.line.Path, held.line.Line))
			}
			entry.Environments = strings.Join(r.Graph.Environments(credential.Key), ", ")
			page.Credentials = append(page.Credentials, entry)
		}
	}
	page.Coverage = r.htmlCoverage()
	return page
}

func (r Report) htmlCoverage() htmlCoverage {
	c := r.Coverage
	coverage := htmlCoverage{LogSources: c.LogSources}
	if len(c.FilesScanned) > 0 {
		coverage.Scanned = fmt.Sprintf("%d (%s)", c.TotalScanned(), kindSummary(c))
	}
	coverage.SkippedTotal = c.TotalSkipped()
	for index, skip := range c.FilesSkipped {
		if index == maxListedSkips {
			coverage.SkippedMore = c.TotalSkipped() - maxListedSkips
			break
		}
		coverage.Skipped = append(coverage.Skipped, skip)
	}
	for _, span := range c.TimeRanges {
		coverage.Ranges = append(coverage.Ranges, fmt.Sprintf("%s: %s to %s", span.Source, span.From.UTC().Format("2006-01-02T15:04:05Z"), span.To.UTC().Format("2006-01-02T15:04:05Z")))
	}
	coverage.Rules, coverage.Detail = splitUnverified(c.UnverifiedRules)
	coverage.Detail = capitalizeFirst(coverage.Detail)
	return coverage
}
