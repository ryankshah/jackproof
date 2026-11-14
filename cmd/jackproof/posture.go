package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/ryankshah/jackproof/internal/finding"
	"github.com/ryankshah/jackproof/internal/posture"
	"github.com/ryankshah/jackproof/internal/scan"
)

func runPosture(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("posture", flag.ContinueOnError)
	var flags commonFlags
	flags.register(fs, "text")
	live := fs.Bool("live", false, "also run read-only live checks: AWS Bedrock logging with AWS credentials in the environment, and with --gcp-project or --azure-subscription, Vertex AI audit logs or Azure OpenAI diagnostic settings with a token from the environment")
	region := fs.String("region", "", "AWS region for --live (default: AWS_REGION or AWS_DEFAULT_REGION)")
	gcpProject := fs.String("gcp-project", "", "Google Cloud project for --live. Needs GOOGLE_OAUTH_ACCESS_TOKEN, for example from gcloud auth print-access-token")
	azureSubscription := fs.String("azure-subscription", "", "Azure subscription id for --live. Needs AZURE_ACCESS_TOKEN, for example from az account get-access-token")
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
		liveFindings, sources, err := livePass(kit, liveTargets{region: *region, gcpProject: *gcpProject, azureSubscription: *azureSubscription})
		if err != nil {
			return err
		}
		findings = append(findings, liveFindings...)
		finding.Sort(findings)
		coverage.LogSources = append(coverage.LogSources, sources...)
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

type liveTargets struct {
	region            string
	gcpProject        string
	azureSubscription string
}

func livePass(kit toolkit, targets liveTargets) ([]finding.Finding, []string, error) {
	var findings []finding.Finding
	var sources []string
	credentials, credentialsErr := posture.CredentialsFromEnvironment()
	if credentialsErr == nil || targets.region != "" {
		if credentialsErr != nil {
			return nil, nil, fmt.Errorf("%w: %w", errUsage, credentialsErr)
		}
		region := targets.region
		if region == "" {
			region = posture.RegionFromEnvironment()
		}
		found, err := posture.CheckBedrockLogging(context.Background(), posture.LiveOptions{Region: region, Credentials: credentials, Rules: kit.rules})
		if err != nil {
			return nil, nil, fmt.Errorf("live check of AWS: %w", err)
		}
		findings = append(findings, found...)
		sources = append(sources, "live: AWS Bedrock invocation logging in "+region)
	}
	if targets.gcpProject != "" {
		token := os.Getenv(posture.GoogleTokenVariable)
		if token == "" {
			return nil, nil, fmt.Errorf("%w: --gcp-project needs %s in the environment", errUsage, posture.GoogleTokenVariable)
		}
		found, err := posture.CheckVertexLogging(context.Background(), targets.gcpProject, posture.TokenOptions{Token: token, Rules: kit.rules})
		if err != nil {
			return nil, nil, fmt.Errorf("live check of Google Cloud: %w", err)
		}
		findings = append(findings, found...)
		sources = append(sources, "live: Vertex AI Data Access audit logs in project "+targets.gcpProject)
	}
	if targets.azureSubscription != "" {
		token := os.Getenv(posture.AzureTokenVariable)
		if token == "" {
			return nil, nil, fmt.Errorf("%w: --azure-subscription needs %s in the environment", errUsage, posture.AzureTokenVariable)
		}
		found, err := posture.CheckAzureDiagnostics(context.Background(), targets.azureSubscription, posture.TokenOptions{Token: token, Rules: kit.rules})
		if err != nil {
			return nil, nil, fmt.Errorf("live check of Azure: %w", err)
		}
		findings = append(findings, found...)
		sources = append(sources, "live: Azure OpenAI diagnostic settings in subscription "+targets.azureSubscription)
	}
	if len(sources) == 0 {
		return nil, nil, fmt.Errorf("%w: live mode needs AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY in the environment, or --gcp-project, or --azure-subscription", errUsage)
	}
	return findings, sources, nil
}
