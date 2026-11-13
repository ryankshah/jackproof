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
	"time"

	"go.yaml.in/yaml/v3"
)

const FileName = "jackproof.yaml"

type Ignore struct {
	Paths []string `yaml:"paths"`
	Rules []string `yaml:"rules"`
}

type Config struct {
	Ignore            Ignore              `yaml:"ignore"`
	Environments      map[string][]string `yaml:"environments"`
	ExpectedProviders map[string][]string `yaml:"expected_providers"`
	OwnedAccounts     []string            `yaml:"owned_accounts"`
	Hunt              Hunt                `yaml:"hunt"`

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

func (c *Config) ExpectedProvidersFor(environment string) ([]string, bool) {
	providers, configured := c.ExpectedProviders[environment]
	return providers, configured
}

func (c *Config) OwnsAccount(id string) bool {
	for _, owned := range c.OwnedAccounts {
		if owned == id {
			return true
		}
	}
	return false
}

type Hunt struct {
	EnableThenInvokeWindow time.Duration `yaml:"enable_then_invoke_window"`
	VolumeMultiplier       float64       `yaml:"volume_multiplier"`
	VolumePeriod           time.Duration `yaml:"volume_period"`
	BaselinePeriods        int           `yaml:"baseline_periods"`
	BaselineMinPeriods     int           `yaml:"baseline_min_periods"`
	MinRequests            int           `yaml:"min_requests"`
	MinHistory             int           `yaml:"min_history"`
	HighCostModels         []string      `yaml:"high_cost_models"`
	DistinctIPs            int           `yaml:"distinct_ips"`
	DistinctIPWindow       time.Duration `yaml:"distinct_ip_window"`
	KeyUseWindow           time.Duration `yaml:"key_use_window"`
	ReconWindow            time.Duration `yaml:"recon_window"`
	StreamConcurrency      int           `yaml:"stream_concurrency"`
	StreamWindow           time.Duration `yaml:"stream_window"`
	UniformShare           float64       `yaml:"uniform_share"`
	KnownNetworks          []string      `yaml:"known_networks"`
}

func DefaultHunt() Hunt {
	return Hunt{
		EnableThenInvokeWindow: time.Hour,
		VolumeMultiplier:       5,
		VolumePeriod:           time.Hour,
		BaselinePeriods:        24,
		BaselineMinPeriods:     3,
		MinRequests:            20,
		MinHistory:             20,
		HighCostModels:         []string{"*opus*", "*gpt-4*", "*o1*", "*ultra*"},
		DistinctIPs:            5,
		DistinctIPWindow:       10 * time.Minute,
		KeyUseWindow:           10 * time.Minute,
		ReconWindow:            30 * time.Minute,
		StreamConcurrency:      20,
		StreamWindow:           time.Minute,
		UniformShare:           0.9,
	}
}

func (c *Config) HuntSettings() Hunt {
	defaults := DefaultHunt()
	settings := c.Hunt
	if settings.EnableThenInvokeWindow == 0 {
		settings.EnableThenInvokeWindow = defaults.EnableThenInvokeWindow
	}
	if settings.VolumeMultiplier == 0 {
		settings.VolumeMultiplier = defaults.VolumeMultiplier
	}
	if settings.VolumePeriod == 0 {
		settings.VolumePeriod = defaults.VolumePeriod
	}
	if settings.BaselinePeriods == 0 {
		settings.BaselinePeriods = defaults.BaselinePeriods
	}
	if settings.BaselineMinPeriods == 0 {
		settings.BaselineMinPeriods = defaults.BaselineMinPeriods
	}
	if settings.MinRequests == 0 {
		settings.MinRequests = defaults.MinRequests
	}
	if settings.MinHistory == 0 {
		settings.MinHistory = defaults.MinHistory
	}
	if len(settings.HighCostModels) == 0 {
		settings.HighCostModels = defaults.HighCostModels
	}
	if settings.DistinctIPs == 0 {
		settings.DistinctIPs = defaults.DistinctIPs
	}
	if settings.DistinctIPWindow == 0 {
		settings.DistinctIPWindow = defaults.DistinctIPWindow
	}
	if settings.KeyUseWindow == 0 {
		settings.KeyUseWindow = defaults.KeyUseWindow
	}
	if settings.ReconWindow == 0 {
		settings.ReconWindow = defaults.ReconWindow
	}
	if settings.StreamConcurrency == 0 {
		settings.StreamConcurrency = defaults.StreamConcurrency
	}
	if settings.StreamWindow == 0 {
		settings.StreamWindow = defaults.StreamWindow
	}
	if settings.UniformShare == 0 {
		settings.UniformShare = defaults.UniformShare
	}
	return settings
}
