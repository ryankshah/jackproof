package lang

import (
	"bytes"
	_ "embed"
	"fmt"
	"regexp"
	"strings"

	"go.yaml.in/yaml/v3"
)

//go:embed lookups.yaml
var embeddedLookups []byte

type SecretLookup struct {
	Store string
	Name  string
	Line  int
}

type lookupRule struct {
	Store    string `yaml:"store"`
	Pattern  string `yaml:"pattern"`
	Verified bool   `yaml:"verified"`

	compiled *regexp.Regexp
}

func parseLookups(data []byte) ([]lookupRule, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var rules []lookupRule
	if err := decoder.Decode(&rules); err != nil {
		return nil, fmt.Errorf("parse secret lookup patterns: %w", err)
	}
	for i := range rules {
		if rules[i].Store == "" {
			return nil, fmt.Errorf("secret lookup pattern %d has no store", i)
		}
		compiled, err := regexp.Compile(rules[i].Pattern)
		if err != nil {
			return nil, fmt.Errorf("secret lookup pattern for %s: %w", rules[i].Store, err)
		}
		if compiled.NumSubexp() != 1 {
			return nil, fmt.Errorf("secret lookup pattern for %s needs exactly one capture group", rules[i].Store)
		}
		rules[i].compiled = compiled
	}
	return rules, nil
}

func (e *Extractor) lookups(data []byte, comment string) []SecretLookup {
	var found []SecretLookup
	for index, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), comment) {
			continue
		}
		for _, rule := range e.lookupRules {
			for _, match := range rule.compiled.FindAllStringSubmatch(line, -1) {
				found = append(found, SecretLookup{Store: rule.Store, Name: match[1], Line: index + 1})
			}
		}
	}
	return found
}

func (e *Extractor) UnverifiedLookups() []string {
	var out []string
	for _, rule := range e.lookupRules {
		if !rule.Verified {
			out = append(out, rule.Store)
		}
	}
	return out
}
