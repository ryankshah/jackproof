package rules

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/ryankshah/jackproof/internal/finding"
	embedded "github.com/ryankshah/jackproof/rules"
)

var idPattern = regexp.MustCompile(`^JP-(KEY|POS|HUNT|EXP)-[0-9]{3}$`)

var moduleByFamily = map[string]finding.Module{
	"KEY":  finding.ModuleScan,
	"POS":  finding.ModulePosture,
	"HUNT": finding.ModuleHunt,
	"EXP":  finding.ModuleExposure,
}

type Rule struct {
	ID          string           `yaml:"id"`
	Title       string           `yaml:"title"`
	Severity    finding.Severity `yaml:"severity"`
	Provider    string           `yaml:"provider"`
	Verified    bool             `yaml:"verified"`
	Description string           `yaml:"description"`
	Remediation string           `yaml:"remediation"`
	Refs        []string         `yaml:"refs"`
	Pattern     string           `yaml:"pattern"`
	Matcher     string           `yaml:"matcher"`

	compiled *regexp.Regexp
}

func (r Rule) Module() finding.Module {
	return moduleByFamily[strings.Split(r.ID, "-")[1]]
}

func (r Rule) Regexp() *regexp.Regexp {
	return r.compiled
}

func (r Rule) NewFinding(method finding.Method, confidence finding.Confidence, evidence ...finding.Evidence) finding.Finding {
	f := finding.Finding{
		ID:          finding.NewID(r.ID, evidence[0]),
		Rule:        r.ID,
		Module:      r.Module(),
		Title:       r.Title,
		Severity:    r.Severity,
		Confidence:  confidence,
		Evidence:    evidence,
		Method:      method,
		Remediation: r.Remediation,
		Refs:        append([]string(nil), r.Refs...),
	}
	if !r.Verified {
		f.Flags = append(f.Flags, finding.FlagUnverifiedRule)
	}
	return f
}

func (r Rule) validate(fileName string) error {
	if !idPattern.MatchString(r.ID) {
		return fmt.Errorf("id %q does not match JP-(KEY|POS|HUNT|EXP)-NNN", r.ID)
	}
	if fileName != r.ID+".yaml" {
		return fmt.Errorf("file name must be %s.yaml", r.ID)
	}
	if r.Title == "" {
		return errors.New("title is required")
	}
	if !r.Severity.Valid() {
		return fmt.Errorf("severity %q is not valid", r.Severity)
	}
	if r.Description == "" {
		return errors.New("description is required")
	}
	if r.Remediation == "" {
		return errors.New("remediation is required")
	}
	if (r.Pattern == "") == (r.Matcher == "") {
		return errors.New("exactly one of pattern or matcher is required")
	}
	for _, ref := range r.Refs {
		if !strings.HasPrefix(ref, "https://") {
			return fmt.Errorf("reference %q must be an https URL", ref)
		}
	}
	return nil
}

type Catalogue struct {
	rules map[string]Rule
}

func LoadEmbedded() (*Catalogue, error) {
	catalogue, err := Load(embedded.FS)
	if err != nil {
		return nil, fmt.Errorf("load embedded rules: %w", err)
	}
	return catalogue, nil
}

func Load(fsys fs.FS) (*Catalogue, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, fmt.Errorf("read rules directory: %w", err)
	}
	catalogue := &Catalogue{rules: make(map[string]Rule)}
	for _, entry := range entries {
		if entry.IsDir() || path.Ext(entry.Name()) != ".yaml" {
			continue
		}
		rule, err := loadRule(fsys, entry.Name())
		if err != nil {
			return nil, err
		}
		if _, exists := catalogue.rules[rule.ID]; exists {
			return nil, fmt.Errorf("duplicate rule id %s", rule.ID)
		}
		catalogue.rules[rule.ID] = rule
	}
	return catalogue, nil
}

func loadRule(fsys fs.FS, name string) (Rule, error) {
	data, err := fs.ReadFile(fsys, name)
	if err != nil {
		return Rule{}, fmt.Errorf("read rule %s: %w", name, err)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var rule Rule
	if err := decoder.Decode(&rule); err != nil {
		return Rule{}, fmt.Errorf("parse rule %s: %w", name, err)
	}
	if err := rule.validate(name); err != nil {
		return Rule{}, fmt.Errorf("rule %s: %w", name, err)
	}
	if rule.Pattern != "" {
		rule.compiled, err = regexp.Compile(rule.Pattern)
		if err != nil {
			return Rule{}, fmt.Errorf("rule %s pattern: %w", name, err)
		}
	}
	return rule, nil
}

func (c *Catalogue) Merge(extra *Catalogue) (*Catalogue, error) {
	merged := &Catalogue{rules: make(map[string]Rule, len(c.rules)+len(extra.rules))}
	for id, rule := range c.rules {
		merged.rules[id] = rule
	}
	for id, rule := range extra.rules {
		if _, exists := merged.rules[id]; exists {
			return nil, fmt.Errorf("rule %s is already defined", id)
		}
		merged.rules[id] = rule
	}
	return merged, nil
}

func (c *Catalogue) Get(id string) (Rule, bool) {
	rule, ok := c.rules[id]
	return rule, ok
}

func (c *Catalogue) All() []Rule {
	all := make([]Rule, 0, len(c.rules))
	for _, rule := range c.rules {
		all = append(all, rule)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].ID < all[j].ID })
	return all
}

func (c *Catalogue) Unverified() []Rule {
	var unverified []Rule
	for _, rule := range c.All() {
		if !rule.Verified {
			unverified = append(unverified, rule)
		}
	}
	return unverified
}
