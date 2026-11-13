package main

import (
	"flag"
	"fmt"
	"io"

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
	return scanAndEmit(stdout, flags, defaultPaths(paths), "jackproof scan")
}

func scanAndEmit(stdout io.Writer, flags commonFlags, paths []string, title string) error {
	kit, err := loadToolkit(flags, paths[0])
	if err != nil {
		return err
	}
	scanner, err := scan.New(kit.cfg, kit.rules, kit.secrets)
	if err != nil {
		return fmt.Errorf("prepare scan: %w", err)
	}
	result, err := scanner.Run(paths)
	if err != nil {
		return fmt.Errorf("scan: %w", err)
	}
	return emit(stdout, flags, kit, title, result)
}
