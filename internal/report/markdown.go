package report

import (
	"io"
	"strings"

	"github.com/ryankshah/jackproof/internal/finding"
)

func WriteMarkdown(w io.Writer, r Report) error {
	p := &printer{w: w}
	p.printf("# %s\n\n%s\n", r.Title, summary(r.Findings))
	if len(r.Findings) == 0 {
		p.printf("\n%s\n", noFindingsNote)
	} else {
		p.printf("\n| Severity | Confidence | Rule | Finding | Location |\n| --- | --- | --- | --- | --- |\n")
		for _, f := range r.Findings {
			p.printf("| %s | %s | %s | %s | %s |\n", f.Severity, f.Confidence, f.Rule, cell(f.Title), cell(location(f.Evidence[0])))
		}
		p.printf("\n## Findings\n")
		for _, f := range r.Findings {
			writeMarkdownFinding(p, f)
		}
	}
	writeMarkdownGraph(p, r)
	for _, extra := range r.Extras {
		p.printf("\n## %s\n\n%s\n", extra.Title, extra.Text)
	}
	writeMarkdownCoverage(p, r.Coverage)
	return p.err
}

func writeMarkdownFinding(p *printer, f finding.Finding) {
	p.printf("\n### %s %s: %s\n\n", strings.ToUpper(string(f.Severity)), f.Rule, f.Title)
	p.printf("- Confidence: %s\n- Method: %s\n- Finding id: `%s`\n", f.Confidence, f.Method, f.ID)
	if len(f.Flags) > 0 {
		p.printf("- Flags: %s\n", joinFlags(f.Flags))
	}
	p.printf("\nEvidence:\n\n```text\n")
	for _, evidence := range f.Evidence {
		p.printf("%s\n", location(evidence))
		if evidence.Excerpt != "" {
			p.printf("    %s\n", evidence.Excerpt)
		}
	}
	p.printf("```\n")
	if len(f.Unproven) > 0 {
		p.printf("\nNot established:\n\n")
		for _, unproven := range f.Unproven {
			p.printf("- %s\n", unproven)
		}
	}
	p.printf("\nFix: %s\n", f.Remediation)
	if len(f.Refs) > 0 {
		p.printf("\nReferences:\n\n")
		for _, ref := range f.Refs {
			p.printf("- %s\n", ref)
		}
	}
}

func writeMarkdownGraph(p *printer, r Report) {
	if r.Graph == nil || len(r.Graph.Credentials()) == 0 {
		return
	}
	p.printf("\n## Credential graph\n")
	for _, credential := range r.Graph.Credentials() {
		p.printf("\n### %s %s\n\n", r.providerName(credential.Provider), credentialLabel(credential))
		for _, definition := range credential.Definitions {
			p.printf("- Defined at `%s:%d`\n", definition.Path, definition.Line)
		}
		for _, held := range credentialHolders(r.Graph, credential.Key) {
			p.printf("- Held by %s via %s at `%s:%d`\n", holderLabel(held.holder), held.delivery, held.line.Path, held.line.Line)
		}
		if environments := r.Graph.Environments(credential.Key); len(environments) > 0 {
			p.printf("- Environments: %s\n", strings.Join(environments, ", "))
		}
		if credential.Reach != "" {
			p.printf("- If a holder is compromised: %s\n", credential.Reach)
		}
	}
}

func writeMarkdownCoverage(p *printer, c finding.Coverage) {
	p.printf("\n## Coverage\n\n")
	if len(c.FilesScanned) > 0 {
		p.printf("- Files scanned: %d (%s)\n", c.TotalScanned(), kindSummary(c))
	}
	if len(c.FilesSkipped) > 0 {
		p.printf("- Files skipped: %d\n", len(c.FilesSkipped))
		for i, skip := range c.FilesSkipped {
			if i == maxListedSkips {
				p.printf("  - and %d more\n", len(c.FilesSkipped)-maxListedSkips)
				break
			}
			p.printf("  - `%s`: %s\n", skip.Path, skip.Reason)
		}
	}
	for _, source := range c.LogSources {
		p.printf("- Log source: %s\n", source)
	}
	for _, span := range c.TimeRanges {
		p.printf("- Time range for %s: %s to %s\n", span.Source, span.From.UTC().Format("2006-01-02T15:04:05Z"), span.To.UTC().Format("2006-01-02T15:04:05Z"))
	}
	ruleIDs, formats, clients := splitUnverified(c.UnverifiedRules)
	if len(ruleIDs) > 0 {
		p.printf("- Rules not verified against provider documentation: %s\n", strings.Join(ruleIDs, ", "))
	}
	if formats > 0 || clients > 0 {
		p.printf("- Provider key formats not verified: %d. SDK client patterns not verified: %d.\n", formats, clients)
	}
}

func cell(text string) string {
	return strings.ReplaceAll(strings.ReplaceAll(text, "|", `\|`), "\n", " ")
}
