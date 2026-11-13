package main

import (
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/ryankshah/jackproof/internal/finding"
	"github.com/ryankshah/jackproof/internal/gitrepo"
	"github.com/ryankshah/jackproof/internal/report"
	"github.com/ryankshah/jackproof/internal/scan"
)

func runScan(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	var flags commonFlags
	flags.register(fs, "text")
	staged := fs.Bool("staged", false, "scan the staged content of the current git repository instead of paths")
	paths, helped, err := parseFlags(fs, args, stdout)
	if err != nil || helped {
		return err
	}
	if *staged {
		if len(paths) > 0 {
			return fmt.Errorf("%w: --staged does not take paths", errUsage)
		}
		return scanStaged(stdout, flags)
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

func scanStaged(stdout io.Writer, flags commonFlags) (err error) {
	top, err := gitrepo.Toplevel(".")
	if err != nil {
		return err
	}
	files, err := gitrepo.StagedFiles(top)
	if err != nil {
		return err
	}
	snapshot, cleanup, err := gitrepo.StageSnapshot(top, files)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, cleanup()) }()
	kit, err := loadToolkit(flags, top)
	if err != nil {
		return err
	}
	result, err := runScanner(kit, []string{snapshot})
	if err != nil {
		return err
	}
	rep := reportFor("jackproof scan (staged files)", result.Findings, result.Coverage)
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
