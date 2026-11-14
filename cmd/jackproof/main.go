package main

import (
	"errors"
	"fmt"
	"io"
	"os"
)

var version = "dev"

const (
	exitOK       = 0
	exitFindings = 1
	exitUsage    = 2
)

var (
	errFindings = errors.New("findings at or above the fail-on severity")
	errUsage    = errors.New("usage error")
)

const usageText = `usage: jackproof <command> [flags] [arguments]

commands:
  scan [path...]       find LLM credentials and the workloads that can read them
  posture [path...]    evaluate whether model services can be enabled and abused
  report [path...]     build one report across modules
  diff <base> <head>   report findings added between two git revisions
  explain <id> [path...]  show the full evidence behind one finding
  hunt --source <type> <files...>  look for LLMjacking in exported logs
  hunt export-sigma    write Sigma rules for the detections
  exposure [path...]   locate exposed credentials and plan their rotation
  exposure verify      check that old credentials no longer authenticate
  rules list           list the rule catalogue
  rules show <id>      show one rule
  version              print the version

Run "jackproof <command> -h" for the flags of a command.
Exit codes: 0 no findings at or above --fail-on, 1 findings found, 2 usage or runtime error.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	err := dispatch(args, stdin, stdout)
	switch {
	case err == nil:
		return exitOK
	case errors.Is(err, errFindings):
		return exitFindings
	default:
		_, _ = fmt.Fprintf(stderr, "jackproof: %v\n", err)
		return exitUsage
	}
}

func dispatch(args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("%w\n\n%s", errUsage, usageText)
	}
	command, rest := args[0], args[1:]
	switch command {
	case "scan":
		return runScan(rest, stdout)
	case "report":
		return runReport(rest, stdin, stdout)
	case "posture":
		return runPosture(rest, stdout)
	case "diff":
		return runDiff(rest, stdout)
	case "explain":
		return runExplain(rest, stdout)
	case "hunt":
		return runHunt(rest, stdout)
	case "exposure":
		return runExposure(rest, stdin, stdout)
	case "rules":
		return runRules(rest, stdout)
	case "version":
		return writeLine(stdout, version)
	case "help", "-h", "--help":
		return writeLine(stdout, usageText)
	}
	return fmt.Errorf("%w: unknown command %q\n\n%s", errUsage, command, usageText)
}

func writeLine(w io.Writer, text string) error {
	if _, err := fmt.Fprintln(w, text); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	return nil
}
