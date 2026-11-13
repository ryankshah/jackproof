package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/ryankshah/jackproof/internal/config"
	"github.com/ryankshah/jackproof/internal/finding"
	"github.com/ryankshah/jackproof/internal/report"
	"github.com/ryankshah/jackproof/internal/rules"
	"github.com/ryankshah/jackproof/internal/scan"
	"github.com/ryankshah/jackproof/internal/secret"
)

type commonFlags struct {
	configPath    string
	rulesDir      string
	format        string
	minConfidence string
	failOn        string
}

func (c *commonFlags) register(fs *flag.FlagSet, defaultFormat string) {
	fs.StringVar(&c.configPath, "config", "", "path to jackproof.yaml (default: jackproof.yaml in the first path)")
	fs.StringVar(&c.rulesDir, "rules-dir", "", "directory with additional rule files")
	fs.StringVar(&c.format, "format", defaultFormat, "output format: text, json, sarif or md")
	fs.StringVar(&c.minConfidence, "min-confidence", "", "hide findings below this confidence: high, medium or low")
	fs.StringVar(&c.failOn, "fail-on", "high", "exit with status 1 when a finding has at least this severity")
}

func (c commonFlags) filter() (finding.Filter, finding.Severity, error) {
	var filter finding.Filter
	if c.minConfidence != "" {
		confidence, err := finding.ParseConfidence(c.minConfidence)
		if err != nil {
			return filter, "", fmt.Errorf("%w: --min-confidence: %w", errUsage, err)
		}
		filter.MinConfidence = confidence
	}
	threshold, err := finding.ParseSeverity(c.failOn)
	if err != nil {
		return filter, "", fmt.Errorf("%w: --fail-on: %w", errUsage, err)
	}
	return filter, threshold, nil
}

func parseFlags(fs *flag.FlagSet, args []string, stdout io.Writer) ([]string, bool, error) {
	fs.SetOutput(io.Discard)
	var positional []string
	for {
		err := fs.Parse(args)
		if errors.Is(err, flag.ErrHelp) {
			fs.SetOutput(stdout)
			if _, writeErr := fmt.Fprintf(stdout, "usage: jackproof %s [flags] [arguments]\n\n", fs.Name()); writeErr != nil {
				return nil, false, fmt.Errorf("write help: %w", writeErr)
			}
			fs.PrintDefaults()
			return nil, true, nil
		}
		if err != nil {
			return nil, false, fmt.Errorf("%w: %s: %w", errUsage, fs.Name(), err)
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return positional, false, nil
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}
}

type toolkit struct {
	cfg     *config.Config
	rules   *rules.Catalogue
	secrets *secret.Catalogue
}

func loadToolkit(flags commonFlags, anchor string) (toolkit, error) {
	var kit toolkit
	var err error
	if flags.configPath != "" {
		kit.cfg, err = config.Load(flags.configPath)
	} else {
		kit.cfg, err = config.LoadIfPresent(anchorDirectory(anchor))
	}
	if err != nil {
		return kit, err
	}
	if kit.rules, err = rules.LoadEmbedded(); err != nil {
		return kit, err
	}
	if flags.rulesDir != "" {
		extra, loadErr := rules.Load(os.DirFS(flags.rulesDir))
		if loadErr != nil {
			return kit, fmt.Errorf("load rules from %s: %w", flags.rulesDir, loadErr)
		}
		if kit.rules, err = kit.rules.Merge(extra); err != nil {
			return kit, err
		}
	}
	if kit.secrets, err = secret.LoadCatalogue(); err != nil {
		return kit, err
	}
	return kit, nil
}

func anchorDirectory(path string) string {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	if info, statErr := os.Stat(absolute); statErr == nil && !info.IsDir() {
		return filepath.Dir(absolute)
	}
	return absolute
}

func (k toolkit) providerNames() map[string]string {
	names := make(map[string]string)
	for _, provider := range k.secrets.Providers() {
		names[provider.ID] = provider.Name
	}
	return names
}

func defaultPaths(paths []string) []string {
	if len(paths) == 0 {
		return []string{"."}
	}
	return paths
}

func emit(stdout io.Writer, flags commonFlags, kit toolkit, title string, result *scan.Result) error {
	filter, threshold, err := flags.filter()
	if err != nil {
		return err
	}
	findings := filter.Apply(result.Findings)
	rep := report.Report{
		Title:     title,
		Version:   version,
		Findings:  findings,
		Coverage:  result.Coverage,
		Graph:     result.Graph,
		Rules:     kit.rules,
		Providers: kit.providerNames(),
	}
	if err := report.Write(stdout, flags.format, rep); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	if highest, found := finding.HighestSeverity(findings); found && highest.AtLeast(threshold) {
		return errFindings
	}
	return nil
}
