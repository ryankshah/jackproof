package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

const FileName = "jackproof.yaml"

type Ignore struct {
	Paths []string `yaml:"paths"`
	Rules []string `yaml:"rules"`
}

type Config struct {
	Ignore       Ignore              `yaml:"ignore"`
	Environments map[string][]string `yaml:"environments"`

	ignoreMatchers []*regexp.Regexp
	envMatchers    []environmentMatcher
}

type environmentMatcher struct {
	name    string
	pattern *regexp.Regexp
}

func Default() *Config {
	return &Config{}
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	return Parse(data)
}

func LoadIfPresent(dir string) (*Config, error) {
	cfg, err := Load(filepath.Join(dir, FileName))
	if errors.Is(err, fs.ErrNotExist) {
		return Default(), nil
	}
	return cfg, err
}

func Parse(data []byte) (*Config, error) {
	var cfg Config
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := cfg.compile(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) compile() error {
	for _, glob := range c.Ignore.Paths {
		pattern, err := compileGlob(glob)
		if err != nil {
			return fmt.Errorf("ignore path %q: %w", glob, err)
		}
		c.ignoreMatchers = append(c.ignoreMatchers, pattern)
	}
	names := make([]string, 0, len(c.Environments))
	for name := range c.Environments {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		for _, glob := range c.Environments[name] {
			pattern, err := compileGlob(glob)
			if err != nil {
				return fmt.Errorf("environment %q glob %q: %w", name, glob, err)
			}
			c.envMatchers = append(c.envMatchers, environmentMatcher{name: name, pattern: pattern})
		}
	}
	return nil
}

func (c *Config) IgnoresPath(path string) bool {
	slashed := filepath.ToSlash(path)
	for _, pattern := range c.ignoreMatchers {
		if pattern.MatchString(slashed) {
			return true
		}
	}
	return false
}

func (c *Config) IgnoresRule(id string) bool {
	for _, ignored := range c.Ignore.Rules {
		if ignored == id {
			return true
		}
	}
	return false
}

func (c *Config) EnvironmentForPath(path string) string {
	slashed := filepath.ToSlash(path)
	for _, matcher := range c.envMatchers {
		if matcher.pattern.MatchString(slashed) {
			return matcher.name
		}
	}
	return ""
}

func compileGlob(glob string) (*regexp.Regexp, error) {
	var builder strings.Builder
	builder.WriteString("^")
	runes := []rune(filepath.ToSlash(glob))
	for i := 0; i < len(runes); i++ {
		switch r := runes[i]; r {
		case '*':
			if i+1 < len(runes) && runes[i+1] == '*' {
				i++
				if i+1 < len(runes) && runes[i+1] == '/' {
					i++
					builder.WriteString("(?:.*/)?")
				} else {
					builder.WriteString(".*")
				}
			} else {
				builder.WriteString("[^/]*")
			}
		case '?':
			builder.WriteString("[^/]")
		default:
			builder.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	builder.WriteString("$")
	return regexp.Compile(builder.String())
}
