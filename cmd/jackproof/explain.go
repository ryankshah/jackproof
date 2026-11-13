package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ryankshah/jackproof/internal/finding"
	"github.com/ryankshah/jackproof/internal/rules"
)

const minIDPrefix = 6

func runExplain(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("explain", flag.ContinueOnError)
	var flags commonFlags
	flags.register(fs, "text")
	from := fs.String("from", "", "read findings from a JSON report instead of analysing paths")
	positional, helped, err := parseFlags(fs, args, stdout)
	if err != nil || helped {
		return err
	}
	if len(positional) == 0 {
		return fmt.Errorf("%w: explain needs a finding id", errUsage)
	}
	id, paths := strings.ToLower(positional[0]), positional[1:]
	if len(id) < minIDPrefix {
		return fmt.Errorf("%w: a finding id needs at least %d characters", errUsage, minIDPrefix)
	}
	if flags.format != "text" && flags.format != "json" {
		return fmt.Errorf("%w: explain supports the text and json formats", errUsage)
	}

	anchor := "."
	if len(paths) > 0 {
		anchor = paths[0]
	}
	kit, err := loadToolkit(flags, anchor)
	if err != nil {
		return err
	}
	var findings []finding.Finding
	if *from != "" {
		findings, err = readFindings(*from)
	} else {
		var result analysis
		result, err = analyzeAll(kit, defaultPaths(paths))
		findings = result.findings
	}
	if err != nil {
		return err
	}
	match, err := findByID(findings, id)
	if err != nil {
		return err
	}
	if flags.format == "json" {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(match); err != nil {
			return fmt.Errorf("write finding: %w", err)
		}
		return nil
	}
	return writeExplanation(stdout, match, kit.rules)
}

func readFindings(path string) ([]finding.Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read report: %w", err)
	}
	var document struct {
		Findings []finding.Finding `json:"findings"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, fmt.Errorf("%w: --from must be a JSON report from jackproof: %w", errUsage, err)
	}
	return document.Findings, nil
}

func findByID(findings []finding.Finding, id string) (finding.Finding, error) {
	var matches []finding.Finding
	for _, f := range findings {
		if strings.HasPrefix(f.ID, id) {
			matches = append(matches, f)
		}
	}
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return finding.Finding{}, fmt.Errorf("%w: no finding has the id %q in this analysis. Ids depend on the rule and the location, so analyse the same paths that produced the id, or pass a saved report with --from", errUsage, id)
	}
	return finding.Finding{}, fmt.Errorf("%w: the id prefix %q matches %d findings. Use a longer prefix", errUsage, id, len(matches))
}

func writeExplanation(w io.Writer, f finding.Finding, catalogue *rules.Catalogue) error {
	var builder strings.Builder
	fmt.Fprintf(&builder, "%s  %s\n%s\n\n", f.ID, f.Rule, f.Title)
	fmt.Fprintf(&builder, "severity:   %s\nconfidence: %s\nmodule:     %s\nmethod:     %s\n", f.Severity, f.Confidence, f.Module, f.Method)
	if len(f.Flags) > 0 {
		parts := make([]string, len(f.Flags))
		for i, flag := range f.Flags {
			parts[i] = string(flag)
		}
		fmt.Fprintf(&builder, "flags:      %s\n", strings.Join(parts, ", "))
	}
	builder.WriteString("\nevidence\n")
	for _, evidence := range f.Evidence {
		if evidence.Path != "" {
			fmt.Fprintf(&builder, "  %s:%d-%d\n", evidence.Path, evidence.StartLine, evidence.EndLine)
		} else {
			fmt.Fprintf(&builder, "  record %s at %s\n", evidence.Record, evidence.Timestamp.UTC().Format("2006-01-02T15:04:05Z"))
		}
		if evidence.Excerpt != "" {
			fmt.Fprintf(&builder, "    %s\n", evidence.Excerpt)
		}
	}
	if len(f.Unproven) > 0 {
		builder.WriteString("\nnot established\n")
		for _, item := range f.Unproven {
			fmt.Fprintf(&builder, "  %s\n", item)
		}
	}
	fmt.Fprintf(&builder, "\nfix\n  %s\n", strings.ReplaceAll(f.Remediation, "\n", "\n  "))
	if rule, ok := catalogue.Get(f.Rule); ok {
		verified := "verified against provider documentation"
		if !rule.Verified {
			verified = "not verified against provider documentation"
		}
		fmt.Fprintf(&builder, "\nrule\n  %s\n  This rule is %s.\n", rule.Description, verified)
	}
	if len(f.Refs) > 0 {
		builder.WriteString("\nreferences\n")
		for _, ref := range f.Refs {
			fmt.Fprintf(&builder, "  %s\n", ref)
		}
	}
	if _, err := io.WriteString(w, builder.String()); err != nil {
		return fmt.Errorf("write explanation: %w", err)
	}
	return nil
}
