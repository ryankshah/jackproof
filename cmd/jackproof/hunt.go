package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ryankshah/jackproof/internal/finding"
	"github.com/ryankshah/jackproof/internal/graph"
	"github.com/ryankshah/jackproof/internal/hunt"
	"github.com/ryankshah/jackproof/internal/hunt/source"
)

func runHunt(args []string, stdout io.Writer) error {
	if len(args) > 0 && args[0] == "export-sigma" {
		return runExportSigma(args[1:], stdout)
	}
	fs := flag.NewFlagSet("hunt", flag.ContinueOnError)
	var flags commonFlags
	flags.register(fs, "text")
	sourceType := fs.String("source", "", "log source type: "+strings.Join(source.Types, ", "))
	graphPath := fs.String("graph", "", "JSON report from jackproof scan, used to cross-reference code with invocations")
	networkMap := fs.String("asn-map", "", "CSV file with cidr, asn, org and class columns for source address enrichment")
	usageColumns := fs.String("usage-columns", "", "column names of a usage CSV, for example timestamp=ts,principal=key_id")
	files, helped, err := parseFlags(fs, args, stdout)
	if err != nil || helped {
		return err
	}
	if *sourceType == "" || len(files) == 0 {
		return fmt.Errorf("%w: hunt needs --source and at least one log file", errUsage)
	}
	columns, err := source.ParseColumns(*usageColumns)
	if err != nil {
		return fmt.Errorf("%w: --usage-columns: %w", errUsage, err)
	}
	kit, err := loadToolkit(flags, ".")
	if err != nil {
		return err
	}
	code, err := loadCodeMap(*graphPath)
	if err != nil {
		return err
	}
	findings, coverage, err := huntPass(kit, huntInput{sourceType: *sourceType, files: files, columns: columns, networkMap: *networkMap, code: code})
	if err != nil {
		return err
	}
	return emit(stdout, flags, kit, reportFor("jackproof hunt", findings, coverage))
}

type huntInput struct {
	sourceType string
	files      []string
	columns    map[string]string
	networkMap string
	code       hunt.CodeMap
}

func huntPass(kit toolkit, input huntInput) ([]finding.Finding, finding.Coverage, error) {
	var events []source.Event
	var coverage finding.Coverage
	for _, file := range input.files {
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, coverage, fmt.Errorf("read log file: %w", err)
		}
		loaded, err := source.Load(input.sourceType, file, data, source.UsageOptions{Columns: input.columns})
		if err != nil {
			return nil, coverage, err
		}
		events = append(events, loaded.Events...)
		coverage.LogSources = append(coverage.LogSources, describeSource(input.sourceType, file, loaded))
		if span, ok := timeRange(file, loaded.Events); ok {
			coverage.TimeRanges = append(coverage.TimeRanges, span)
		}
	}
	networks, err := loadNetworks(kit.cfg.Hunt.KnownNetworks, input.networkMap)
	if err != nil {
		return nil, coverage, err
	}
	findings, err := hunt.Analyze(events, hunt.Options{Config: kit.cfg, Rules: kit.rules, Networks: networks, Code: input.code})
	if err != nil {
		return nil, coverage, fmt.Errorf("analyse logs: %w", err)
	}
	for _, rule := range kit.rules.Unverified() {
		if rule.Module() == finding.ModuleHunt {
			coverage.UnverifiedRules = append(coverage.UnverifiedRules, rule.ID)
		}
	}
	return findings, coverage, nil
}

func codeMapFromGraph(g *graph.Graph) hunt.CodeMap {
	code := hunt.CodeMap{Loaded: true, Providers: make(map[string]bool)}
	for _, holder := range g.Holders() {
		for _, provider := range holder.Providers {
			code.Providers[provider] = true
		}
	}
	return code
}

func describeSource(sourceType, file string, loaded source.Result) string {
	description := fmt.Sprintf("%s: %s, %d relevant events", sourceType, file, len(loaded.Events))
	if loaded.Skipped > 0 {
		description += fmt.Sprintf(", %d records skipped", loaded.Skipped)
	}
	if sourceType == source.TypeAzure {
		description += ". The Activity Log does not record model invocations"
	}
	return description
}

func timeRange(file string, events []source.Event) (finding.TimeRange, bool) {
	if len(events) == 0 {
		return finding.TimeRange{}, false
	}
	first, last := events[0].Time, events[0].Time
	for _, event := range events {
		if event.Time.Before(first) {
			first = event.Time
		}
		if event.Time.After(last) {
			last = event.Time
		}
	}
	return finding.TimeRange{Source: file, From: first, To: last}, true
}

func loadNetworks(known []string, mapPath string) (*hunt.Networks, error) {
	networks, err := hunt.NewNetworks(known)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errUsage, err)
	}
	if mapPath == "" {
		return networks, nil
	}
	data, err := os.ReadFile(mapPath)
	if err != nil {
		return nil, fmt.Errorf("read network map: %w", err)
	}
	if err := networks.LoadMap(data); err != nil {
		return nil, fmt.Errorf("%w: %w", errUsage, err)
	}
	return networks, nil
}

func loadCodeMap(path string) (hunt.CodeMap, error) {
	if path == "" {
		return hunt.CodeMap{}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return hunt.CodeMap{}, fmt.Errorf("read scan report: %w", err)
	}
	var document struct {
		Graph struct {
			Holders []struct {
				Providers []string `json:"providers"`
			} `json:"holders"`
		} `json:"graph"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		return hunt.CodeMap{}, fmt.Errorf("%w: --graph must be a JSON report from jackproof scan: %w", errUsage, err)
	}
	code := hunt.CodeMap{Loaded: true, Providers: make(map[string]bool)}
	for _, holder := range document.Graph.Holders {
		for _, provider := range holder.Providers {
			code.Providers[provider] = true
		}
	}
	return code, nil
}

func runExportSigma(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("hunt export-sigma", flag.ContinueOnError)
	var flags commonFlags
	flags.register(fs, "text")
	_, helped, err := parseFlags(fs, args, stdout)
	if err != nil || helped {
		return err
	}
	kit, err := loadToolkit(flags, ".")
	if err != nil {
		return err
	}
	return hunt.ExportSigma(stdout, kit.cfg.HuntSettings())
}
