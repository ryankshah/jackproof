package main

import (
	"errors"
	"fmt"
	"io"
	"os"
)

var version = "dev"

const (
	exitOK    = 0
	exitUsage = 2
)

var errUsage = errors.New("usage: jackproof <command>\ncommands: version")

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "jackproof: %v\n", err)
		os.Exit(exitUsage)
	}
	os.Exit(exitOK)
}

func run(args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return errUsage
	}
	switch args[0] {
	case "version":
		if _, err := fmt.Fprintln(stdout, version); err != nil {
			return fmt.Errorf("write version: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("unknown command %q\n%w", args[0], errUsage)
	}
}
