package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ryankshah/jackproof/internal/exposure"
	"github.com/ryankshah/jackproof/internal/report"
	"github.com/ryankshah/jackproof/internal/scan"
	"github.com/ryankshah/jackproof/internal/secret"
)

func runExposure(args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) > 0 && args[0] == "verify" {
		return runExposureVerify(args[1:], stdin, stdout)
	}
	fs := flag.NewFlagSet("exposure", flag.ContinueOnError)
	var flags commonFlags
	flags.register(fs, "md")
	fingerprints := fs.String("fingerprints", "", "file with one fingerprint per line")
	names := fs.String("secret-names", "", "file with one secret name per line")
	keysStdin := fs.Bool("keys-stdin", false, "read raw keys from standard input, one per line. Keys are hashed in memory and never stored")
	algo := fs.String("fp-algo", secret.AlgoSHA256, "algorithm of the fingerprints in --fingerprints: "+strings.Join(secret.Algorithms(), ", "))
	paths, helped, err := parseFlags(fs, args, stdout)
	if err != nil || helped {
		return err
	}
	paths = defaultPaths(paths)

	targets, err := collectTargets(*fingerprints, *names, *keysStdin, *algo, stdin)
	if err != nil {
		return err
	}
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
	analysis, err := exposure.Analyze(result, targets, kit.rules, kit.secrets)
	if err != nil {
		return fmt.Errorf("analyse exposure: %w", err)
	}

	var plan bytes.Buffer
	if err := analysis.Plan.WriteMarkdown(&plan); err != nil {
		return err
	}
	rep := report.Report{
		Title:    "jackproof exposure",
		Findings: analysis.Findings,
		Coverage: result.Coverage,
		Extras:   []report.Extra{{Key: "rotation_plan", Title: "Rotation plan", Text: plan.String(), Data: analysis.Plan}},
	}
	return emit(stdout, flags, kit, rep)
}

func collectTargets(fingerprintsPath, namesPath string, keysStdin bool, algo string, stdin io.Reader) ([]exposure.Target, error) {
	var targets []exposure.Target
	if fingerprintsPath != "" {
		data, err := os.ReadFile(fingerprintsPath)
		if err != nil {
			return nil, fmt.Errorf("read fingerprints: %w", err)
		}
		parsed, err := exposure.ParseFingerprints(algo, fingerprintsPath, data)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", errUsage, err)
		}
		targets = append(targets, parsed...)
	}
	if namesPath != "" {
		data, err := os.ReadFile(namesPath)
		if err != nil {
			return nil, fmt.Errorf("read secret names: %w", err)
		}
		parsed, err := exposure.ParseNames(namesPath, data)
		if err != nil {
			return nil, err
		}
		targets = append(targets, parsed...)
	}
	if keysStdin {
		data, err := io.ReadAll(stdin)
		if err != nil {
			return nil, fmt.Errorf("read keys from standard input: %w", err)
		}
		targets = append(targets, exposure.TargetsFromKeys(data)...)
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("%w: exposure needs at least one of --fingerprints, --secret-names or --keys-stdin", errUsage)
	}
	return targets, nil
}

func runExposureVerify(args []string, stdin io.Reader, stdout io.Writer) error {
	fs := flag.NewFlagSet("exposure verify", flag.ContinueOnError)
	var flags commonFlags
	flags.register(fs, "text")
	keysStdin := fs.Bool("keys-stdin", false, "read keys from standard input, one per line")
	live := fs.Bool("verify-live", false, "send one read-only metadata request per key to its provider")
	owned := fs.Bool("i-own-these-keys", false, "confirm that you own the credentials you are checking")
	timeout := fs.Duration("timeout", exposure.DefaultTimeout, "time limit for each request")
	_, helped, err := parseFlags(fs, args, stdout)
	if err != nil || helped {
		return err
	}
	switch {
	case !*keysStdin:
		return fmt.Errorf("%w: exposure verify needs --keys-stdin", errUsage)
	case !*live:
		return fmt.Errorf("%w: exposure verify contacts provider APIs and needs --verify-live", errUsage)
	case !*owned:
		return fmt.Errorf("%w: exposure verify needs --i-own-these-keys to confirm that you own the credentials", errUsage)
	}

	data, err := io.ReadAll(stdin)
	if err != nil {
		return fmt.Errorf("read keys from standard input: %w", err)
	}
	kit, err := loadToolkit(flags, ".")
	if err != nil {
		return err
	}
	results, err := exposure.NewVerifier(kit.secrets, *timeout).CheckAll(context.Background(), data)
	if err != nil {
		return err
	}
	if len(results) == 0 {
		return fmt.Errorf("%w: no keys were provided on standard input", errUsage)
	}
	findings, err := exposure.ResultFindings(results, kit.rules)
	if err != nil {
		return err
	}
	rep := report.Report{
		Title:    "jackproof exposure verify",
		Findings: findings,
		Extras:   []report.Extra{{Key: "verification", Title: "Verification results", Text: exposure.ResultsText(results), Data: results}},
	}
	if err := emit(stdout, flags, kit, rep); err != nil {
		return err
	}
	if !exposure.AllRejected(results) {
		return errFindings
	}
	return nil
}
