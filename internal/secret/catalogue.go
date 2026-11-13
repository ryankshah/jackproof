package secret

import (
	"bytes"
	_ "embed"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

//go:embed providers.yaml
var embeddedProviders []byte

type Format struct {
	Name     string `yaml:"name"`
	Pattern  string `yaml:"pattern"`
	Context  bool   `yaml:"context"`
	Verified bool   `yaml:"verified"`
}

type Provider struct {
	ID      string   `yaml:"id"`
	Name    string   `yaml:"name"`
	EnvVars []string `yaml:"env_vars"`
	Refs    []string `yaml:"refs"`
	Reach   string   `yaml:"reach"`
	Formats []Format `yaml:"formats"`
}

type compiledFormat struct {
	provider *Provider
	format   Format
	re       *regexp.Regexp
}

type Catalogue struct {
	providers []Provider
	compiled  []compiledFormat
	byEnvVar  map[string]string
}

func LoadCatalogue() (*Catalogue, error) {
	return parseCatalogue(embeddedProviders)
}

func parseCatalogue(data []byte) (*Catalogue, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var providers []Provider
	if err := decoder.Decode(&providers); err != nil {
		return nil, fmt.Errorf("parse provider catalogue: %w", err)
	}
	catalogue := &Catalogue{providers: providers, byEnvVar: make(map[string]string)}
	seen := make(map[string]bool)
	for i := range catalogue.providers {
		provider := &catalogue.providers[i]
		if provider.ID == "" || provider.Name == "" {
			return nil, fmt.Errorf("provider %d needs an id and a name", i)
		}
		if provider.Reach == "" {
			return nil, fmt.Errorf("provider %q has no reach description", provider.ID)
		}
		if seen[provider.ID] {
			return nil, fmt.Errorf("duplicate provider id %q", provider.ID)
		}
		seen[provider.ID] = true
		if len(provider.Formats) == 0 {
			return nil, fmt.Errorf("provider %q has no formats", provider.ID)
		}
		for _, name := range provider.EnvVars {
			catalogue.byEnvVar[name] = provider.ID
		}
		for _, format := range provider.Formats {
			re, err := compileFormat(provider, format)
			if err != nil {
				return nil, err
			}
			catalogue.compiled = append(catalogue.compiled, compiledFormat{provider: provider, format: format, re: re})
		}
	}
	return catalogue, nil
}

func compileFormat(provider *Provider, format Format) (*regexp.Regexp, error) {
	if format.Name == "" || format.Pattern == "" {
		return nil, fmt.Errorf("provider %q has a format without a name or pattern", provider.ID)
	}
	expression := `(?:^|[^A-Za-z0-9])(` + format.Pattern + `)`
	if format.Context {
		if len(provider.EnvVars) == 0 {
			return nil, fmt.Errorf("provider %q format %q is context-only but the provider has no env vars", provider.ID, format.Name)
		}
		names := make([]string, len(provider.EnvVars))
		for i, name := range provider.EnvVars {
			names[i] = regexp.QuoteMeta(name)
		}
		expression = `(?i:\b(?:` + strings.Join(names, "|") + `))["']?\s*[:=]\s*["']?(` + format.Pattern + `)(?:[^A-Za-z0-9_/+=-]|$)`
	}
	re, err := regexp.Compile(expression)
	if err != nil {
		return nil, fmt.Errorf("provider %q format %q pattern: %w", provider.ID, format.Name, err)
	}
	return re, nil
}

func (c *Catalogue) Providers() []Provider {
	return append([]Provider(nil), c.providers...)
}

func (c *Catalogue) Provider(id string) (Provider, bool) {
	for _, provider := range c.providers {
		if provider.ID == id {
			return provider, true
		}
	}
	return Provider{}, false
}

func (c *Catalogue) ProviderForEnvVar(name string) (string, bool) {
	id, ok := c.byEnvVar[name]
	return id, ok
}

func (c *Catalogue) EnvVars() []string {
	names := make([]string, 0, len(c.byEnvVar))
	for name := range c.byEnvVar {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

type UnverifiedFormat struct {
	Provider string
	Format   string
}

func (c *Catalogue) Unverified() []UnverifiedFormat {
	var out []UnverifiedFormat
	for _, compiled := range c.compiled {
		if !compiled.format.Verified {
			out = append(out, UnverifiedFormat{Provider: compiled.provider.ID, Format: compiled.format.Name})
		}
	}
	return out
}
