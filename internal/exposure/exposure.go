package exposure

import (
	"bufio"
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/ryankshah/jackproof/internal/finding"
	"github.com/ryankshah/jackproof/internal/graph"
	"github.com/ryankshah/jackproof/internal/rules"
	"github.com/ryankshah/jackproof/internal/scan"
	"github.com/ryankshah/jackproof/internal/secret"
)

const (
	ruleLocated           = "JP-EXP-001"
	ruleNotFound          = "JP-EXP-002"
	maxLocations          = 200
	maxEvidence           = 10
	stdinSource           = "stdin"
	fingerprintKind       = "fingerprint"
	nameKind              = "name"
	maxExcerptLength      = 160
	roleDefinition        = "definition"
	roleInjection         = "injection"
	roleReference         = "reference"
	identifierSpecials    = "_-"
	awsSecretSuffixLength = 7
)

type Source struct {
	Path string `json:"path"`
	Line int    `json:"line"`
}

type Target struct {
	Kind   string
	Algo   string
	Value  string
	Source Source
}

func (t Target) Label() string {
	if t.Kind == fingerprintKind {
		return fmt.Sprintf("fingerprint %s (%s)", t.Value[:16], t.Algo)
	}
	return fmt.Sprintf("secret name %s", t.Value)
}

type Location struct {
	Path        string `json:"path"`
	Line        int    `json:"line"`
	Role        string `json:"role"`
	Holder      string `json:"holder,omitempty"`
	HolderKind  string `json:"holder_kind,omitempty"`
	Environment string `json:"environment,omitempty"`
	Delivery    string `json:"delivery,omitempty"`
	Untrusted   bool   `json:"untrusted,omitempty"`
	Excerpt     string `json:"excerpt,omitempty"`
}

type Exposure struct {
	Target      Target
	Provider    string
	Reach       string
	Credentials []graph.Credential
	Locations   []Location
}

type Analysis struct {
	Exposures []Exposure
	Findings  []finding.Finding
	Plan      Plan
}

func ParseFingerprints(algo, path string, data []byte) ([]Target, error) {
	var targets []Target
	scanner := bufio.NewScanner(bytes.NewReader(data))
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		normalized, err := secret.NormalizeDigest(algo, line)
		if err != nil {
			return nil, fmt.Errorf("%s line %d: %w", path, lineNumber, err)
		}
		targets = append(targets, Target{Kind: fingerprintKind, Algo: algo, Value: normalized, Source: Source{Path: path, Line: lineNumber}})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return targets, nil
}

func ParseNames(path string, data []byte) ([]Target, error) {
	var targets []Target
	scanner := bufio.NewScanner(bytes.NewReader(data))
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		targets = append(targets, Target{Kind: nameKind, Value: line, Source: Source{Path: path, Line: lineNumber}})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return targets, nil
}

func TargetsFromKeys(data []byte) []Target {
	var targets []Target
	scanner := bufio.NewScanner(bytes.NewReader(data))
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		key := strings.TrimSpace(scanner.Text())
		if key == "" {
			continue
		}
		targets = append(targets, Target{
			Kind:   fingerprintKind,
			Algo:   secret.AlgoSHA256,
			Value:  secret.Fingerprint(key),
			Source: Source{Path: stdinSource, Line: lineNumber},
		})
	}
	return targets
}

func Analyze(result *scan.Result, targets []Target, ruleSet *rules.Catalogue, secrets *secret.Catalogue) (*Analysis, error) {
	for _, id := range []string{ruleLocated, ruleNotFound} {
		if _, ok := ruleSet.Get(id); !ok {
			return nil, fmt.Errorf("rule catalogue is missing %s", id)
		}
	}
	analyzer := &analyzer{result: result, rules: ruleSet, secrets: secrets, files: make(map[string]*scan.File, len(result.Files))}
	for i := range result.Files {
		analyzer.files[result.Files[i].Path] = &result.Files[i]
	}
	analysis := &Analysis{}
	for _, target := range targets {
		exposure := analyzer.match(target)
		analysis.Exposures = append(analysis.Exposures, exposure)
		analysis.Findings = append(analysis.Findings, analyzer.finding(exposure))
	}
	finding.Sort(analysis.Findings)
	analysis.Plan = BuildPlan(analysis.Exposures)
	return analysis, nil
}

type analyzer struct {
	result  *scan.Result
	rules   *rules.Catalogue
	secrets *secret.Catalogue
	files   map[string]*scan.File
}

func (a *analyzer) match(target Target) Exposure {
	exposure := Exposure{Target: target}
	covered := make(map[string]bool)
	for _, credential := range a.result.Graph.Credentials() {
		if !matches(credential, target) {
			continue
		}
		exposure.Credentials = append(exposure.Credentials, credential)
		if exposure.Provider == "" {
			exposure.Provider = credential.Provider
			exposure.Reach = credential.Reach
		}
		for _, definition := range credential.Definitions {
			exposure.Locations = append(exposure.Locations, a.location(definition.Path, definition.Line, roleDefinition, graph.Holder{}, ""))
			covered[lineKey(definition.Path, definition.Line)] = true
		}
		for _, edge := range a.result.Graph.EdgesOf(credential.Key) {
			holder, _ := a.result.Graph.Holder(edge.Holder)
			exposure.Locations = append(exposure.Locations, a.location(edge.Location.Path, edge.Location.Line, roleInjection, holder, string(edge.Delivery)))
			covered[lineKey(edge.Location.Path, edge.Location.Line)] = true
		}
	}
	if target.Kind == nameKind {
		exposure.Locations = append(exposure.Locations, a.nameReferences(target.Value, covered)...)
	}
	sortLocations(exposure.Locations)
	if len(exposure.Locations) > maxLocations {
		exposure.Locations = exposure.Locations[:maxLocations]
	}
	return exposure
}

func matches(credential graph.Credential, target Target) bool {
	if target.Kind == fingerprintKind {
		digest, ok := credential.Digests[target.Algo]
		return credential.Kind == graph.KindLiteral && ok && strings.HasPrefix(digest, target.Value)
	}
	if credential.Kind != graph.KindReference {
		return false
	}
	for _, name := range referenceNames(credential.Name) {
		if name == target.Value {
			return true
		}
	}
	return false
}

func referenceNames(identity string) []string {
	kind, rest, found := strings.Cut(identity, ":")
	if !found {
		return []string{identity}
	}
	names := []string{rest}
	switch kind {
	case "k8s-secret":
		if secretName, key, hasKey := strings.Cut(rest, "/"); hasKey {
			names = append(names, secretName, key)
		}
	case "aws-secret":
		if _, name, isARN := strings.Cut(rest, ":secret:"); isARN {
			names = append(names, name)
			if cut := len(name) - awsSecretSuffixLength; cut > 0 && name[cut] == '-' {
				names = append(names, name[:cut])
			}
		}
	}
	return names
}

func (a *analyzer) location(path string, line int, role string, holder graph.Holder, delivery string) Location {
	location := Location{Path: path, Line: line, Role: role, Delivery: delivery}
	if holder.ID != "" {
		location.Holder = holder.Name
		location.HolderKind = string(holder.Kind)
		location.Environment = holder.Environment
		location.Untrusted = holder.Untrusted
	}
	if file, ok := a.files[path]; ok {
		location.Excerpt = a.excerpt(file, line)
	}
	return location
}

func (a *analyzer) excerpt(file *scan.File, line int) string {
	lines := strings.Split(string(file.Data), "\n")
	if line < 1 || line > len(lines) {
		return ""
	}
	text := strings.TrimSpace(a.secrets.RedactLine(strings.TrimRight(lines[line-1], "\r")))
	if len(text) > maxExcerptLength {
		return text[:maxExcerptLength] + "..."
	}
	return text
}

func (a *analyzer) nameReferences(name string, covered map[string]bool) []Location {
	var found []Location
	for _, file := range a.result.Files {
		for index, line := range strings.Split(string(file.Data), "\n") {
			if !containsToken(line, name) || covered[lineKey(file.Path, index+1)] {
				continue
			}
			role := roleReference
			if file.Kind == "dotenv" && strings.HasPrefix(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "export ")), name+"=") {
				role = roleDefinition
			}
			location := Location{Path: file.Path, Line: index + 1, Role: role}
			location.Excerpt = a.excerpt(&file, index+1)
			found = append(found, location)
			if len(found) >= maxLocations {
				return found
			}
		}
	}
	return found
}

func containsToken(line, token string) bool {
	for offset := 0; ; {
		index := strings.Index(line[offset:], token)
		if index < 0 {
			return false
		}
		start := offset + index
		end := start + len(token)
		if (start == 0 || !isIdentifier(line[start-1])) && (end == len(line) || !isIdentifier(line[end])) {
			return true
		}
		offset = start + 1
	}
}

func isIdentifier(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || strings.IndexByte(identifierSpecials, b) >= 0
}

func lineKey(path string, line int) string {
	return fmt.Sprintf("%s:%d", path, line)
}

var roleRank = map[string]int{roleDefinition: 0, roleInjection: 1, roleReference: 2}

func sortLocations(locations []Location) {
	sort.SliceStable(locations, func(i, j int) bool {
		a, b := locations[i], locations[j]
		if roleRank[a.Role] != roleRank[b.Role] {
			return roleRank[a.Role] < roleRank[b.Role]
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.Line < b.Line
	})
}

func (a *analyzer) finding(exposure Exposure) finding.Finding {
	target := exposure.Target
	if len(exposure.Locations) == 0 {
		rule, _ := a.rules.Get(ruleNotFound)
		method := finding.MethodFingerprintMatch
		if target.Kind == nameKind {
			method = finding.MethodPattern
		}
		f := rule.NewFinding(method, finding.ConfidenceHigh, finding.Evidence{
			Path: target.Source.Path, StartLine: target.Source.Line, EndLine: target.Source.Line, Excerpt: target.Label(),
		})
		f.Title = fmt.Sprintf("%s was not found in the scanned paths", capitalize(target.Label()))
		f.Flags = append(f.Flags, finding.FlagIncomplete)
		f.Unproven = []string{"Whether the credential is used outside the scanned paths, such as other repositories, CI settings, secret managers or deployed systems."}
		return f
	}

	rule, _ := a.rules.Get(ruleLocated)
	evidence := make([]finding.Evidence, 0, maxEvidence)
	for _, location := range exposure.Locations {
		if len(evidence) == maxEvidence {
			break
		}
		evidence = append(evidence, finding.Evidence{Path: location.Path, StartLine: location.Line, EndLine: location.Line, Excerpt: location.Excerpt})
	}
	confidence := finding.ConfidenceHigh
	method := finding.MethodFingerprintMatch
	var flags []finding.Flag
	var unproven []string
	if target.Kind == nameKind {
		confidence = finding.ConfidenceMedium
		method = finding.MethodPattern
		flags = []finding.Flag{finding.FlagInferred}
		unproven = []string{"Whether this name refers to the same stored secret as the one in the exposure notice."}
	}
	f := rule.NewFinding(method, confidence, evidence...)
	f.Title = fmt.Sprintf("%s appears in %d %s", capitalize(target.Label()), len(exposure.Locations), pluralize("location", len(exposure.Locations)))
	f.Flags = append(f.Flags, flags...)
	f.Unproven = append(f.Unproven, unproven...)
	f.Unproven = append(f.Unproven, "Whether the credential is also held outside the scanned paths.")
	return f
}

func capitalize(text string) string {
	if text == "" {
		return text
	}
	return strings.ToUpper(text[:1]) + text[1:]
}

func pluralize(noun string, count int) string {
	if count == 1 {
		return noun
	}
	return noun + "s"
}
