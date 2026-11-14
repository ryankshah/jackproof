package main

import (
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/ryankshah/jackproof/internal/exposure"
	"github.com/ryankshah/jackproof/internal/finding"
	"github.com/ryankshah/jackproof/internal/hunt/source"
	"github.com/ryankshah/jackproof/internal/secret"
)

type listFlag []string

func (l *listFlag) String() string {
	return strings.Join(*l, ",")
}

func (l *listFlag) Set(value string) error {
	*l = append(*l, value)
	return nil
}

func runReport(args []string, stdin io.Reader, stdout io.Writer) error {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	var flags commonFlags
	flags.register(fs, "md")
	var logs listFlag
	fs.Var(&logs, "logs", "log file for hunt, repeatable. Needs --logs-source")
	logsSource := fs.String("logs-source", "", "log source type for --logs: "+strings.Join(source.Types, ", "))
	networkMap := fs.String("asn-map", "", "CSV file with cidr, asn, org and class columns for hunt")
	usageColumns := fs.String("usage-columns", "", "column names of a usage CSV for hunt")
	fingerprints := fs.String("fingerprints", "", "file with one fingerprint per line, for exposure")
	names := fs.String("secret-names", "", "file with one secret name per line, for exposure")
	keysStdin := fs.Bool("keys-stdin", false, "read raw keys from standard input for exposure. Keys are hashed in memory and never stored")
	algo := fs.String("fp-algo", secret.AlgoSHA256, "algorithm of the fingerprints in --fingerprints: "+strings.Join(secret.Algorithms(), ", "))
	paths, helped, err := parseFlags(fs, args, stdout)
	if err != nil || helped {
		return err
	}
	if len(logs) > 0 && *logsSource == "" {
		return fmt.Errorf("%w: --logs needs --logs-source", errUsage)
	}
	columns, err := source.ParseColumns(*usageColumns)
	if err != nil {
		return fmt.Errorf("%w: --usage-columns: %w", errUsage, err)
	}
	paths = defaultPaths(paths)
	kit, err := loadToolkit(flags, paths[0])
	if err != nil {
		return err
	}
	exposureRequested := *fingerprints != "" || *names != "" || *keysStdin
	var targets []exposure.Target
	if exposureRequested {
		if targets, err = collectTargets(*fingerprints, *names, *keysStdin, *algo, stdin); err != nil {
			return err
		}
	}

	result, err := analyzeAll(kit, paths)
	if err != nil {
		return err
	}
	findings := append([]finding.Finding(nil), result.findings...)
	coverage := result.coverage
	rep := reportFor("jackproof report", nil, finding.Coverage{})
	rep.Graph = result.graph

	if len(logs) > 0 {
		huntFindings, huntCoverage, err := huntPass(kit, huntInput{
			sourceType: *logsSource, files: logs, columns: columns, networkMap: *networkMap, code: codeMapFromGraph(result.graph),
		})
		if err != nil {
			return err
		}
		findings = append(findings, huntFindings...)
		coverage.Merge(huntCoverage)
	}
	if exposureRequested {
		exposureFindings, extra, err := exposurePass(kit, result.scan, targets)
		if err != nil {
			return err
		}
		findings = append(findings, exposureFindings...)
		rep.Extras = append(rep.Extras, extra)
	}

	finding.Sort(findings)
	rep.Findings, rep.Coverage = findings, coverage
	return emit(stdout, flags, kit, rep)
}
