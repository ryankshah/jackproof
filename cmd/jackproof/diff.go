package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/ryankshah/jackproof/internal/diff"
	"github.com/ryankshah/jackproof/internal/finding"
	"github.com/ryankshah/jackproof/internal/gitrepo"
	"github.com/ryankshah/jackproof/internal/report"
)

type diffSummary struct {
	Added     int            `json:"added"`
	Removed   []diffEntry    `json:"removed"`
	Changed   []changedEntry `json:"changed"`
	Unchanged int            `json:"unchanged"`
}

type diffEntry struct {
	Rule     string           `json:"rule"`
	Title    string           `json:"title"`
	Severity finding.Severity `json:"severity"`
}

type changedEntry struct {
	Rule             string             `json:"rule"`
	Title            string             `json:"title"`
	SeverityBefore   finding.Severity   `json:"severity_before"`
	SeverityAfter    finding.Severity   `json:"severity_after"`
	ConfidenceBefore finding.Confidence `json:"confidence_before"`
	ConfidenceAfter  finding.Confidence `json:"confidence_after"`
}

func runDiff(args []string, stdout io.Writer) (err error) {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	var flags commonFlags
	flags.register(fs, "text")
	revisions, helped, err := parseFlags(fs, args, stdout)
	if err != nil || helped {
		return err
	}
	if len(revisions) != 2 {
		return fmt.Errorf("%w: diff needs a base revision and a head revision", errUsage)
	}
	base, head := revisions[0], revisions[1]

	top, err := gitrepo.Toplevel(".")
	if err != nil {
		return err
	}
	baseTree, cleanBase, err := gitrepo.Checkout(top, base)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, cleanBase()) }()
	headTree, cleanHead, err := gitrepo.Checkout(top, head)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, cleanHead()) }()

	kit, err := loadToolkit(flags, headTree)
	if err != nil {
		return err
	}
	before, err := analyzeAll(kit, []string{baseTree})
	if err != nil {
		return fmt.Errorf("analyse %s: %w", base, err)
	}
	after, err := analyzeAll(kit, []string{headTree})
	if err != nil {
		return fmt.Errorf("analyse %s: %w", head, err)
	}

	result := diff.Compare(before.findings, after.findings)
	rep := reportFor(fmt.Sprintf("jackproof diff %s..%s (findings added in the head revision)", base, head), result.Added, after.coverage)
	rep.Extras = []report.Extra{diffExtra(result)}
	return emit(stdout, flags, kit, rep)
}

func diffExtra(result diff.Result) report.Extra {
	summary := diffSummary{Added: len(result.Added), Unchanged: result.Unchanged, Removed: []diffEntry{}, Changed: []changedEntry{}}
	var text strings.Builder
	fmt.Fprintf(&text, "Added: %d. Removed: %d. Changed: %d. Unchanged: %d.\n", len(result.Added), len(result.Removed), len(result.Changed), result.Unchanged)
	for _, removed := range result.Removed {
		summary.Removed = append(summary.Removed, diffEntry{Rule: removed.Rule, Title: removed.Title, Severity: removed.Severity})
		fmt.Fprintf(&text, "- removed %s %s: %s\n", removed.Severity, removed.Rule, removed.Title)
	}
	for _, change := range result.Changed {
		summary.Changed = append(summary.Changed, changedEntry{
			Rule: change.After.Rule, Title: change.After.Title,
			SeverityBefore: change.Before.Severity, SeverityAfter: change.After.Severity,
			ConfidenceBefore: change.Before.Confidence, ConfidenceAfter: change.After.Confidence,
		})
		fmt.Fprintf(&text, "- changed %s: %s (severity %s to %s, confidence %s to %s)\n", change.After.Rule, change.After.Title,
			change.Before.Severity, change.After.Severity, change.Before.Confidence, change.After.Confidence)
	}
	return report.Extra{Key: "diff", Title: "Changes against the base revision", Text: strings.TrimRight(text.String(), "\n"), Data: summary}
}
