package report

import (
	"io"
	"strings"

	"github.com/ryankshah/jackproof/internal/finding"
)

func WriteText(w io.Writer, r Report) error {
	p := &printer{w: w}
	p.printf("%s: %s\n", r.Title, summary(r.Findings))
	if len(r.Findings) == 0 {
		p.printf("%s\n", noFindingsNote)
	}
	for _, f := range r.Findings {
		p.printf("\n%-8s %s  %s  [%s confidence]\n", strings.ToUpper(string(f.Severity)), f.Rule, f.Title, f.Confidence)
		for _, evidence := range f.Evidence {
			p.printf("         %s\n", location(evidence))
			if evidence.Excerpt != "" {
				p.printf("           %s\n", evidence.Excerpt)
			}
		}
		if len(f.Flags) > 0 {
			p.printf("         flags: %s\n", joinFlags(f.Flags))
		}
		for _, unproven := range f.Unproven {
			p.printf("         not established: %s\n", unproven)
		}
		p.printf("         fix: %s\n", firstParagraph(f.Remediation))
		p.printf("         id: %s\n", f.ID)
	}
	writeTextGraph(p, r)
	for _, extra := range r.Extras {
		p.printf("\n%s\n%s\n", extra.Title, extra.Text)
	}
	writeTextCoverage(p, r.Coverage)
	return p.err
}

func writeTextGraph(p *printer, r Report) {
	if r.Graph == nil || len(r.Graph.Credentials()) == 0 {
		return
	}
	p.printf("\nCredential graph\n")
	for _, credential := range r.Graph.Credentials() {
		p.printf("  %s %s\n", r.providerName(credential.Provider), credentialLabel(credential))
		for _, definition := range credential.Definitions {
			p.printf("    defined at %s:%d\n", definition.Path, definition.Line)
		}
		for _, held := range credentialHolders(r.Graph, credential.Key) {
			p.printf("    held by %s via %s at %s:%d\n", holderLabel(held.holder), held.delivery, held.line.Path, held.line.Line)
		}
		if environments := r.Graph.Environments(credential.Key); len(environments) > 0 {
			p.printf("    environments: %s\n", strings.Join(environments, ", "))
		}
		if credential.Reach != "" {
			p.printf("    if a holder is compromised: %s\n", credential.Reach)
		}
	}
}

func writeTextCoverage(p *printer, c finding.Coverage) {
	p.printf("\nCoverage\n")
	if len(c.FilesScanned) > 0 {
		p.printf("  files scanned: %d (%s)\n", c.TotalScanned(), kindSummary(c))
	}
	if len(c.FilesSkipped) > 0 {
		p.printf("  files skipped: %d\n", len(c.FilesSkipped))
		for i, skip := range c.FilesSkipped {
			if i == maxListedSkips {
				p.printf("    and %d more\n", len(c.FilesSkipped)-maxListedSkips)
				break
			}
			p.printf("    %s: %s\n", skip.Path, skip.Reason)
		}
	}
	for _, source := range c.LogSources {
		p.printf("  log source: %s\n", source)
	}
	for _, span := range c.TimeRanges {
		p.printf("  time range for %s: %s to %s\n", span.Source, span.From.UTC().Format("2006-01-02T15:04:05Z"), span.To.UTC().Format("2006-01-02T15:04:05Z"))
	}
	ruleIDs, detail := splitUnverified(c.UnverifiedRules)
	if len(ruleIDs) > 0 {
		p.printf("  rules not verified against provider documentation: %s\n", strings.Join(ruleIDs, ", "))
	}
	if detail != "" {
		p.printf("  %s\n", detail)
	}
}

func joinFlags(flags []finding.Flag) string {
	parts := make([]string, len(flags))
	for i, flag := range flags {
		parts[i] = string(flag)
	}
	return strings.Join(parts, ", ")
}

func (r Report) providerName(id string) string {
	if r.Providers != nil {
		if name, ok := r.Providers[id]; ok {
			return name
		}
	}
	return id
}
