package lang

import (
	"bytes"
	_ "embed"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

//go:embed clients.yaml
var embeddedClients []byte

const (
	Go         = "go"
	Python     = "python"
	JavaScript = "javascript"
)

type EnvRead struct {
	Name string
	Line int
}

type Client struct {
	Provider    string
	Constructor string
	Line        int
}

type Leak struct {
	Env      string
	Variable string
	Sink     string
	Line     int
	Strong   bool
}

type Facts struct {
	EnvReads      []EnvRead
	Clients       []Client
	Leaks         []Leak
	SecretLookups []SecretLookup
}

type clientRule struct {
	Provider string `yaml:"provider"`
	Import   string `yaml:"import"`
	Package  string `yaml:"package"`
	Pattern  string `yaml:"pattern"`
	Verified bool   `yaml:"verified"`

	compiled *regexp.Regexp
}

type Extractor struct {
	clients         map[string][]clientRule
	lookupRules     []lookupRule
	isCredentialEnv func(string) bool
}

func New(isCredentialEnv func(string) bool) (*Extractor, error) {
	return newExtractor(embeddedClients, isCredentialEnv)
}

func newExtractor(data []byte, isCredentialEnv func(string) bool) (*Extractor, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	clients := make(map[string][]clientRule)
	if err := decoder.Decode(&clients); err != nil {
		return nil, fmt.Errorf("parse client tables: %w", err)
	}
	for language, rules := range clients {
		for i := range rules {
			rule := &rules[i]
			if rule.Provider == "" {
				return nil, fmt.Errorf("%s client rule %d has no provider", language, i)
			}
			if (rule.Import == "") == (rule.Pattern == "") {
				return nil, fmt.Errorf("%s client rule for %s needs exactly one of import or pattern", language, rule.Provider)
			}
			if rule.Pattern != "" {
				compiled, err := regexp.Compile(rule.Pattern)
				if err != nil {
					return nil, fmt.Errorf("%s client rule for %s: %w", language, rule.Provider, err)
				}
				rule.compiled = compiled
			}
		}
	}
	lookupRules, err := parseLookups(embeddedLookups)
	if err != nil {
		return nil, err
	}
	return &Extractor{clients: clients, lookupRules: lookupRules, isCredentialEnv: isCredentialEnv}, nil
}

func (e *Extractor) Extract(language string, data []byte) (Facts, error) {
	var facts Facts
	var comment string
	switch language {
	case Go:
		parsed, err := e.extractGo(data)
		if err != nil {
			return Facts{}, err
		}
		facts, comment = parsed, "//"
	case Python:
		facts, comment = e.extractLines(data, pythonSyntax(), e.clients[Python]), "#"
	case JavaScript:
		facts, comment = e.extractLines(data, javascriptSyntax(), e.clients[JavaScript]), "//"
	default:
		return Facts{}, fmt.Errorf("unsupported language %q", language)
	}
	facts.SecretLookups = e.lookups(data, comment)
	return facts, nil
}

func (e *Extractor) UnverifiedClients() []string {
	var out []string
	for language, rules := range e.clients {
		for _, rule := range rules {
			if !rule.Verified {
				out = append(out, fmt.Sprintf("%s/%s", language, rule.Provider))
			}
		}
	}
	sort.Strings(out)
	return dedupe(out)
}

func LanguageFor(path string) (string, bool) {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".go":
		return Go, true
	case ".py":
		return Python, true
	case ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts":
		return JavaScript, true
	}
	return "", false
}

func dedupe(sorted []string) []string {
	var out []string
	for i, value := range sorted {
		if i == 0 || value != sorted[i-1] {
			out = append(out, value)
		}
	}
	return out
}
