package main

import (
	"flag"
	"io"

	"github.com/ryankshah/jackproof/internal/finding"
)

func runReport(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	var flags commonFlags
	flags.register(fs, "md")
	paths, helped, err := parseFlags(fs, args, stdout)
	if err != nil || helped {
		return err
	}
	paths = defaultPaths(paths)
	kit, err := loadToolkit(flags, paths[0])
	if err != nil {
		return err
	}
	result, err := runScanner(kit, paths)
	if err != nil {
		return err
	}
	postureFindings, postureCoverage, err := posturePass(kit, result)
	if err != nil {
		return err
	}
	postureCoverage.FilesScanned = nil
	coverage := result.Coverage
	coverage.Merge(postureCoverage)

	findings := append(append([]finding.Finding(nil), result.Findings...), postureFindings...)
	finding.Sort(findings)
	rep := reportFor("jackproof report", findings, coverage)
	rep.Graph = result.Graph
	return emit(stdout, flags, kit, rep)
}
