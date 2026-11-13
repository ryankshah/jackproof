package main

import (
	"flag"
	"fmt"
	"io"

	"github.com/ryankshah/jackproof/internal/finding"
	"github.com/ryankshah/jackproof/internal/report"
	"github.com/ryankshah/jackproof/internal/scan"
)

func runScan(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	var flags commonFlags
	flags.register(fs, "text")
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
	rep := reportFor("jackproof scan", result.Findings, result.Coverage)
	rep.Graph = result.Graph
	return emit(stdout, flags, kit, rep)
}

func runScanner(kit toolkit, paths []string) (*scan.Result, error) {
	scanner, err := scan.New(kit.cfg, kit.rules, kit.secrets)
	if err != nil {
		return nil, fmt.Errorf("prepare scan: %w", err)
	}
	result, err := scanner.Run(paths)
	if err != nil {
		return nil, fmt.Errorf("scan: %w", err)
	}
	return result, nil
}

func reportFor(title string, findings []finding.Finding, coverage finding.Coverage) report.Report {
	return report.Report{Title: title, Findings: findings, Coverage: coverage}
}
