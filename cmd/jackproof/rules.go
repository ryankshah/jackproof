package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/ryankshah/jackproof/internal/rules"
)

func runRules(args []string, stdout io.Writer) error {
	catalogue, err := rules.LoadEmbedded()
	if err != nil {
		return err
	}
	if len(args) == 0 {
		return fmt.Errorf("%w: rules needs a subcommand: list or show <id>", errUsage)
	}
	switch args[0] {
	case "list":
		return listRules(stdout, catalogue)
	case "show":
		if len(args) != 2 {
			return fmt.Errorf("%w: rules show needs one rule id", errUsage)
		}
		return showRule(stdout, catalogue, args[1])
	}
	return fmt.Errorf("%w: unknown rules subcommand %q", errUsage, args[0])
}

func listRules(stdout io.Writer, catalogue *rules.Catalogue) error {
	for _, rule := range catalogue.All() {
		verified := "verified"
		if !rule.Verified {
			verified = "unverified"
		}
		if _, err := fmt.Fprintf(stdout, "%-12s %-9s %-10s %s\n", rule.ID, rule.Severity, verified, rule.Title); err != nil {
			return fmt.Errorf("write rule list: %w", err)
		}
	}
	return nil
}

func showRule(stdout io.Writer, catalogue *rules.Catalogue, id string) error {
	rule, ok := catalogue.Get(strings.ToUpper(id))
	if !ok {
		return fmt.Errorf("%w: no rule with id %q", errUsage, id)
	}
	verified := "yes"
	if !rule.Verified {
		verified = "no"
	}
	_, err := fmt.Fprintf(stdout, "%s\n%s\n\nseverity: %s\nmodule: %s\nverified against provider documentation: %s\n\n%s\n\nfix: %s\n",
		rule.ID, rule.Title, rule.Severity, rule.Module(), verified, rule.Description, rule.Remediation)
	if err != nil {
		return fmt.Errorf("write rule: %w", err)
	}
	for _, ref := range rule.Refs {
		if _, err := fmt.Fprintf(stdout, "ref: %s\n", ref); err != nil {
			return fmt.Errorf("write rule: %w", err)
		}
	}
	return nil
}
