package main

import (
	"flag"
	"io"
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
	result, err := analyzeAll(kit, paths)
	if err != nil {
		return err
	}
	rep := reportFor("jackproof report", result.findings, result.coverage)
	rep.Graph = result.graph
	return emit(stdout, flags, kit, rep)
}
