package main

import (
	"context"
	"flag"
	"fmt"
	"io"

	"github.com/ryankshah/jackproof/internal/finding"
	"github.com/ryankshah/jackproof/internal/posture"
	"github.com/ryankshah/jackproof/internal/scan"
)

func runPosture(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("posture", flag.ContinueOnError)
	var flags commonFlags
	flags.register(fs, "text")
	live := fs.Bool("live", false, "also check AWS Bedrock invocation logging with one signed read-only request, using the AWS credentials in the environment")
	region := fs.String("region", "", "AWS region for --live (default: AWS_REGION or AWS_DEFAULT_REGION)")
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
	findings, coverage, err := posturePass(kit, result)
	if err != nil {
		return err
	}
	if *live {
		liveFindings, source, err := livePass(kit, *region)
		if err != nil {
			return err
		}
		findings = append(findings, liveFindings...)
		finding.Sort(findings)
		coverage.LogSources = append(coverage.LogSources, source)
	}
	return emit(stdout, flags, kit, reportFor("jackproof posture", findings, coverage))
}

func posturePass(kit toolkit, result *scan.Result) ([]finding.Finding, finding.Coverage, error) {
	knowledge, err := posture.LoadKnowledge()
	if err != nil {
		return nil, finding.Coverage{}, err
	}
	sources := make([]posture.Source, 0, len(result.Files))
	for _, file := range result.Files {
		sources = append(sources, posture.Source{Path: file.Path, Data: file.Data})
	}
	infra := posture.Extract(sources, kit.cfg, knowledge)
	findings, err := posture.Analyze(infra, sources, kit.cfg, kit.rules, knowledge)
	if err != nil {
		return nil, finding.Coverage{}, fmt.Errorf("analyse posture: %w", err)
	}
	coverage := infra.Coverage
	for _, rule := range kit.rules.Unverified() {
		if rule.Module() == finding.ModulePosture {
			coverage.UnverifiedRules = append(coverage.UnverifiedRules, rule.ID)
		}
	}
	for _, entry := range knowledge.UnverifiedEntries() {
		coverage.UnverifiedRules = append(coverage.UnverifiedRules, "knowledge:"+entry)
	}
	return findings, coverage, nil
}

func livePass(kit toolkit, region string) ([]finding.Finding, string, error) {
	credentials, err := posture.CredentialsFromEnvironment()
	if err != nil {
		return nil, "", fmt.Errorf("%w: %w", errUsage, err)
	}
	if region == "" {
		region = posture.RegionFromEnvironment()
	}
	findings, err := posture.CheckBedrockLogging(context.Background(), posture.LiveOptions{Region: region, Credentials: credentials, Rules: kit.rules})
	if err != nil {
		return nil, "", fmt.Errorf("live check: %w", err)
	}
	return findings, fmt.Sprintf("live: AWS Bedrock invocation logging in %s. No other live checks exist", region), nil
}
