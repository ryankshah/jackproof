package secret

import (
	"bytes"
	_ "embed"
	"fmt"
	"regexp"
	"strings"

	"go.yaml.in/yaml/v3"
)

//go:embed providers.yaml
var embeddedProviders []byte

type Format struct {
	Name     string   `yaml:"name"`
	Pattern  string   `yaml:"pattern"`
	Context  bool     `yaml:"context"`
	Anchors  []string `yaml:"anchors"`
	Verified bool     `yaml:"verified"`
}

type Provider struct {
	ID      string      `yaml:"id"`
	Name    string      `yaml:"name"`
	EnvVars []string    `yaml:"env_vars"`
	Refs    []string    `yaml:"refs"`
	Aliases []string    `yaml:"aliases"`
	Reach   string      `yaml:"reach"`
	Verify  *VerifySpec `yaml:"verify"`
	Formats []Format    `yaml:"formats"`
}

type compiledFormat struct {
	provider *Provider
	format   Format
	re       *regexp.Regexp
	triggers []string
}

type nameToken struct {
	token    string
	provider string
}

type Catalogue struct {
	providers  []Provider
	compiled   []compiledFormat
	byEnvVar   map[string]string
	nameTokens []nameToken
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
		if provider.Verify != nil {
			if err := provider.Verify.validate(); err != nil {
				return nil, fmt.Errorf("provider %q: %w", provider.ID, err)
			}
		}
		if len(provider.Formats) == 0 {
			return nil, fmt.Errorf("provider %q has no formats", provider.ID)
		}
		for _, name := range provider.EnvVars {
			catalogue.byEnvVar[name] = provider.ID
		}
		catalogue.nameTokens = append(catalogue.nameTokens, nameToken{token: strings.ReplaceAll(provider.ID, "-", ""), provider: provider.ID})
		for _, alias := range provider.Aliases {
			catalogue.nameTokens = append(catalogue.nameTokens, nameToken{token: strings.ToLower(alias), provider: provider.ID})
		}
		for _, format := range provider.Formats {
			re, err := compileFormat(provider, format)
			if err != nil {
				return nil, err
			}
			triggers, err := triggersFor(provider, format)
			if err != nil {
				return nil, err
			}
			catalogue.compiled = append(catalogue.compiled, compiledFormat{provider: provider, format: format, re: re, triggers: triggers})
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

func (c *Catalogue) ProviderForName(name string) (string, bool) {
	if id, ok := c.byEnvVar[name]; ok {
		return id, true
	}
	words := strings.FieldsFunc(strings.ToLower(name), func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < '0' || r > '9')
	})
	candidates := make(map[string]struct{}, len(words)*2)
	for i, word := range words {
		candidates[word] = struct{}{}
		if i+1 < len(words) {
			candidates[word+words[i+1]] = struct{}{}
		}
	}
	best := nameToken{}
	for _, entry := range c.nameTokens {
		if _, ok := candidates[entry.token]; ok && len(entry.token) > len(best.token) {
			best = entry
		}
	}
	return best.provider, best.provider != ""
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

type VerifySpec struct {
	URL      string            `yaml:"url"`
	Auth     string            `yaml:"auth"`
	Headers  map[string]string `yaml:"headers"`
	Rejected []int             `yaml:"rejected"`
	Verified bool              `yaml:"verified"`
}

func (v *VerifySpec) validate() error {
	if !strings.HasPrefix(v.URL, "https://") {
		return fmt.Errorf("verify url %q must use https", v.URL)
	}
	if v.Auth != "bearer" && !strings.HasPrefix(v.Auth, "header:") && !strings.HasPrefix(v.Auth, "query:") {
		return fmt.Errorf("verify auth %q must be bearer, header:NAME or query:NAME", v.Auth)
	}
	return nil
}

func triggersFor(provider *Provider, format Format) ([]string, error) {
	if format.Context {
		triggers := make([]string, len(provider.EnvVars))
		for i, name := range provider.EnvVars {
			triggers[i] = strings.ToLower(name)
		}
		return triggers, nil
	}
	prefix, _ := regexp.MustCompile(format.Pattern).LiteralPrefix()
	if prefix != "" {
		return []string{prefix}, nil
	}
	if len(format.Anchors) > 0 {
		return format.Anchors, nil
	}
	return nil, fmt.Errorf("provider %q format %q has no literal prefix, so it needs anchors", provider.ID, format.Name)
}
