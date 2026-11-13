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
	return scanAndEmit(stdout, flags, defaultPaths(paths), "jackproof report")
}
