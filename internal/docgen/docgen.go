package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ryankshah/jackproof/internal/hunt/source"
	"github.com/ryankshah/jackproof/internal/posture"
	"github.com/ryankshah/jackproof/internal/rules"
	"github.com/ryankshah/jackproof/internal/scan/lang"
	"github.com/ryankshah/jackproof/internal/secret"
)

const generatedNotice = "This file is generated from the rule catalogue and the embedded data files. Run `go generate ./...` to update it. Do not edit it by hand."

func main() {
	output := flag.String("out", "docs", "directory for the generated documents")
	flag.Parse()
	if err := generate(*output); err != nil {
		fmt.Fprintf(os.Stderr, "docgen: %v\n", err)
		os.Exit(1)
	}
}

func generate(directory string) error {
	catalogue, err := rules.LoadEmbedded()
	if err != nil {
		return err
	}
	providers, err := secret.LoadCatalogue()
	if err != nil {
		return err
	}
	extractor, err := lang.New(func(string) bool { return false })
	if err != nil {
		return err
	}
	knowledge, err := posture.LoadKnowledge()
	if err != nil {
		return err
	}
	files := map[string]string{
		"rules.md":      renderRules(catalogue),
		"unverified.md": renderUnverified(catalogue, providers, extractor, knowledge),
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(content), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
	}
	return nil
}

func renderRules(catalogue *rules.Catalogue) string {
	var builder strings.Builder
	builder.WriteString("# Rules\n\n" + generatedNotice + "\n\n")
	builder.WriteString("| Rule | Module | Severity | Verified | Title |\n| --- | --- | --- | --- | --- |\n")
	for _, rule := range catalogue.All() {
		fmt.Fprintf(&builder, "| [%s](#%s) | %s | %s | %s | %s |\n", rule.ID, strings.ToLower(rule.ID), rule.Module(), rule.Severity, verifiedWord(rule.Verified), rule.Title)
	}
	for _, rule := range catalogue.All() {
		fmt.Fprintf(&builder, "\n## %s\n\n%s\n\n", rule.ID, rule.Title)
		fmt.Fprintf(&builder, "- Module: %s\n- Severity: %s\n- Verified against provider documentation: %s\n", rule.Module(), rule.Severity, verifiedWord(rule.Verified))
		if rule.Matcher != "" {
			fmt.Fprintf(&builder, "- Matcher: `%s`\n", rule.Matcher)
		}
		fmt.Fprintf(&builder, "\n%s\n\nFix: %s\n", rule.Description, rule.Remediation)
		if len(rule.Refs) > 0 {
			builder.WriteString("\nReferences:\n\n")
			for _, ref := range rule.Refs {
				fmt.Fprintf(&builder, "- %s\n", ref)
			}
		}
	}
	return builder.String()
}

func verifiedWord(verified bool) string {
	if verified {
		return "yes"
	}
	return "no"
}

func renderUnverified(catalogue *rules.Catalogue, providers *secret.Catalogue, extractor *lang.Extractor, knowledge *posture.Knowledge) string {
	var builder strings.Builder
	builder.WriteString("# Unverified facts\n\n" + generatedNotice + "\n\n")
	builder.WriteString("Each entry below is a provider key format, API field, event name or permission that has not been confirmed against the provider's official documentation. Rules that depend on them carry the `unverified-rule` flag.\n")

	section := func(title, introduction string, entries []string) {
		if len(entries) == 0 {
			return
		}
		fmt.Fprintf(&builder, "\n## %s\n\n%s\n\n", title, introduction)
		for _, entry := range entries {
			fmt.Fprintf(&builder, "- %s\n", entry)
		}
	}

	var ruleEntries []string
	for _, rule := range catalogue.Unverified() {
		ruleEntries = append(ruleEntries, fmt.Sprintf("%s: %s", rule.ID, rule.Title))
	}
	section("Rules", "These rules depend on facts that are not yet confirmed.", ruleEntries)

	var formats []string
	for _, entry := range providers.Unverified() {
		formats = append(formats, fmt.Sprintf("%s, format %s", entry.Provider, entry.Format))
	}
	section("Provider key formats", "The patterns that recognise a provider's keys. A wrong pattern causes missed keys or false matches.", formats)

	var endpoints []string
	for _, provider := range providers.Providers() {
		if provider.Verify != nil && !provider.Verify.Verified {
			endpoints = append(endpoints, fmt.Sprintf("%s: GET %s with %s authentication", provider.ID, provider.Verify.URL, provider.Verify.Auth))
		}
	}
	section("Live verification endpoints", "The read-only request that `jackproof exposure verify` sends. The status codes that mean a key was rejected are also unconfirmed.", endpoints)

	section("SDK client patterns", "The constructor calls that `scan` treats as use of a provider.", clientEntries(extractor.UnverifiedClients()))
	section("Cloud permissions and roles", "The action names, permissions and managed roles that `posture` uses to decide what an identity can do.", knowledge.UnverifiedEntries())
	section("Log event and field names", "The names that `hunt` reads from exported logs.", source.UnverifiedNames())

	section("Heuristics", "These are judgements, not provider facts. They affect confidence and are flagged as inferred in findings.", []string{
		"Workload names and images that suggest untrusted code: eval, sandbox, jupyter, notebook, runner, plugin, playground, executor, interpreter.",
		"Environment variable names that suggest a telemetry or crash reporting sink: SENTRY_DSN, DD_API_KEY, NEW_RELIC_LICENSE_KEY, OTEL_EXPORTER_OTLP_ENDPOINT, HONEYCOMB_API_KEY, BUGSNAG_API_KEY, ROLLBAR_ACCESS_TOKEN.",
		"GitHub Actions inputs that carry cloud credentials: aws-access-key-id, aws-secret-access-key, credentials_json.",
		"Model name patterns treated as high cost by default: *opus*, *gpt-4*, *o1*, *ultra*.",
		"The default thresholds of the hunt detections. They are configurable in jackproof.yaml.",
		"The Sigma rules written by `hunt export-sigma`. They have not been run against a live SIEM.",
	})
	return builder.String()
}

func clientEntries(entries []string) []string {
	out := make([]string, len(entries))
	for i, entry := range entries {
		language, provider, _ := strings.Cut(entry, "/")
		out[i] = fmt.Sprintf("%s code, provider %s", language, provider)
	}
	sort.Strings(out)
	return out
}
