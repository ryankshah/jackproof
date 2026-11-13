package scan

import (
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/ryankshah/jackproof/internal/config"
	"github.com/ryankshah/jackproof/internal/finding"
	"github.com/ryankshah/jackproof/internal/graph"
	"github.com/ryankshah/jackproof/internal/rules"
	"github.com/ryankshah/jackproof/internal/scan/lang"
	"github.com/ryankshah/jackproof/internal/secret"
)

const (
	ruleLiteralKey        = "JP-KEY-001"
	ruleCrossEnvironment  = "JP-KEY-010"
	ruleUntrustedWorkload = "JP-KEY-020"
	ruleSharedSink        = "JP-KEY-021"
	ruleStaticCloudKey    = "JP-KEY-030"
	ruleCredentialToSink  = "JP-KEY-040"
	ruleCredentialInImage = "JP-KEY-050"

	maxExcerpt = 160
)

var requiredRules = []string{
	ruleLiteralKey, ruleCrossEnvironment, ruleUntrustedWorkload, ruleSharedSink,
	ruleStaticCloudKey, ruleCredentialToSink, ruleCredentialInImage,
}

type Result struct {
	Findings []finding.Finding
	Graph    *graph.Graph
	Coverage finding.Coverage
	Files    []File
}

type Scanner struct {
	cfg         *config.Config
	rules       *rules.Catalogue
	customRules []rules.Rule
	secrets     *secret.Catalogue
	extractor   *lang.Extractor
}

func New(cfg *config.Config, ruleSet *rules.Catalogue, secrets *secret.Catalogue) (*Scanner, error) {
	for _, id := range requiredRules {
		if _, ok := ruleSet.Get(id); !ok {
			return nil, fmt.Errorf("rule catalogue is missing %s", id)
		}
	}
	extractor, err := lang.New(func(name string) bool {
		_, ok := secrets.ProviderForEnvVar(name)
		return ok
	})
	if err != nil {
		return nil, fmt.Errorf("create language extractor: %w", err)
	}
	var custom []rules.Rule
	for _, rule := range ruleSet.All() {
		if rule.Regexp() != nil {
			custom = append(custom, rule)
		}
	}
	return &Scanner{cfg: cfg, rules: ruleSet, customRules: custom, secrets: secrets, extractor: extractor}, nil
}

type run struct {
	scanner  *Scanner
	graph    *graph.Graph
	findings []finding.Finding
	coverage finding.Coverage
	byPath   map[string]*sourceFile
	seen     map[string]struct{}
}

func (s *Scanner) Run(roots []string) (*Result, error) {
	if len(roots) == 0 {
		return nil, errors.New("no paths to scan")
	}
	base, err := baseDirectory(roots[0])
	if err != nil {
		return nil, err
	}
	r := &run{
		scanner: s,
		graph:   graph.New(),
		byPath:  make(map[string]*sourceFile),
		seen:    make(map[string]struct{}),
	}
	files, err := collectFiles(roots, base, s.cfg, &r.coverage)
	if err != nil {
		return nil, err
	}
	for _, file := range files {
		r.byPath[file.path] = file
	}

	hits := make(map[string][]literalHit)
	for _, file := range files {
		hits[file.path] = r.scanLiterals(file)
	}
	for _, file := range files {
		r.coverage.AddScanned(file.kind)
		r.processStructure(file, hits[file.path])
	}
	r.processTerraform(files)
	r.evaluateRisks()

	r.coverage.UnverifiedRules = s.unverifiedEntries()
	var findings []finding.Finding
	for _, f := range r.findings {
		if !s.cfg.IgnoresRule(f.Rule) {
			findings = append(findings, f)
		}
	}
	finding.Sort(findings)
	return &Result{Findings: findings, Graph: r.graph, Coverage: r.coverage, Files: exportFiles(files)}, nil
}

func (s *Scanner) unverifiedEntries() []string {
	var entries []string
	for _, rule := range s.rules.Unverified() {
		if rule.Module() == finding.ModuleScan {
			entries = append(entries, rule.ID)
		}
	}
	for _, entry := range s.secrets.Unverified() {
		entries = append(entries, fmt.Sprintf("format:%s/%s", entry.Provider, entry.Format))
	}
	for _, entry := range s.extractor.UnverifiedClients() {
		entries = append(entries, "client:"+entry)
	}
	return entries
}

type findingSpec struct {
	rule       string
	title      string
	method     finding.Method
	confidence finding.Confidence
	flags      []finding.Flag
	unproven   []string
	evidence   []finding.Evidence
}

func (r *run) emit(spec findingSpec) {
	rule, _ := r.scanner.rules.Get(spec.rule)
	f := rule.NewFinding(spec.method, spec.confidence, spec.evidence...)
	if spec.title != "" {
		f.Title = spec.title
	}
	f.Flags = append(f.Flags, spec.flags...)
	f.Unproven = spec.unproven
	if _, duplicate := r.seen[f.ID]; duplicate {
		return
	}
	r.seen[f.ID] = struct{}{}
	r.findings = append(r.findings, f)
}

func (r *run) evidenceAt(filePath string, line int) finding.Evidence {
	excerpt := ""
	if file, ok := r.byPath[filePath]; ok {
		excerpt = r.excerpt(file.line(line))
	}
	return finding.Evidence{Path: filePath, StartLine: line, EndLine: line, Excerpt: excerpt}
}

func (r *run) excerpt(line string) string {
	redacted := strings.TrimSpace(r.scanner.secrets.RedactLine(strings.TrimRight(line, "\r")))
	if len(redacted) > maxExcerpt {
		return redacted[:maxExcerpt] + "..."
	}
	return redacted
}

func (r *run) providerName(id string) string {
	if provider, ok := r.scanner.secrets.Provider(id); ok {
		return provider.Name
	}
	return id
}

func (r *run) environmentFor(filePath, explicit, namespace string) string {
	if explicit != "" {
		return explicit
	}
	if environment := r.scanner.cfg.EnvironmentForPath(filePath); environment != "" {
		return environment
	}
	if _, configured := r.scanner.cfg.Environments[namespace]; namespace != "" && configured {
		return namespace
	}
	return ""
}

func directoryOf(filePath string) string {
	directory := path.Dir(filePath)
	if directory == "." {
		return ""
	}
	return directory
}

func joinPath(directory, name string) string {
	return strings.TrimPrefix(path.Join(directory, name), "./")
}

func (r *run) reachOf(id string) string {
	if provider, ok := r.scanner.secrets.Provider(id); ok {
		return provider.Reach
	}
	return ""
}

type File struct {
	Path string
	Kind string
	Data []byte
}

func exportFiles(files []*sourceFile) []File {
	exported := make([]File, len(files))
	for i, file := range files {
		exported[i] = File{Path: file.path, Kind: file.kind, Data: file.data}
	}
	return exported
}
