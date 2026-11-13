package scan

import (
	"strings"

	"github.com/ryankshah/jackproof/internal/finding"
	"github.com/ryankshah/jackproof/internal/graph"
	"github.com/ryankshah/jackproof/internal/secret"
)

const maxScannedLineLength = 20000

type literalHit struct {
	line  int
	match secret.Match
}

func literalKey(fingerprint string) string {
	return graph.CredentialKey(graph.KindLiteral, fingerprint)
}

func referenceKey(identity string) string {
	return graph.CredentialKey(graph.KindReference, identity)
}

func (r *run) scanLiterals(file *sourceFile) []literalHit {
	var hits []literalHit
	example := isExampleFile(file.path)
	for index, line := range strings.Split(string(file.data), "\n") {
		if len(line) > maxScannedLineLength {
			continue
		}
		line = strings.TrimRight(line, "\r")
		number := index + 1
		for _, match := range r.scanner.secrets.Detect(line) {
			hits = append(hits, literalHit{line: number, match: match})
			r.recordLiteral(file, number, match, example)
		}
		r.applyCustomRules(file, number, line)
	}
	return hits
}

func (r *run) recordLiteral(file *sourceFile, line int, match secret.Match, example bool) {
	r.graph.AddCredential(graph.Credential{
		Key:         literalKey(match.Fingerprint),
		Kind:        graph.KindLiteral,
		Provider:    match.Provider,
		Reach:       r.reachOf(match.Provider),
		Redacted:    match.Redacted,
		Fingerprint: match.Fingerprint,
		Definitions: []graph.Location{{Path: file.path, Line: line}},
	})

	confidence := match.Confidence
	unproven := []string{"Whether the key is still active."}
	var flags []finding.Flag
	if match.Confidence != finding.ConfidenceHigh {
		flags = append(flags, finding.FlagInferred)
		unproven = append(unproven, "The value was matched by its variable name, not by a provider-specific prefix.")
	}
	if example {
		confidence = finding.ConfidenceLow
		if !containsFlag(flags, finding.FlagInferred) {
			flags = append(flags, finding.FlagInferred)
		}
		unproven = append(unproven, "The file name suggests a placeholder value.")
	}
	r.emit(findingSpec{
		rule:       ruleLiteralKey,
		title:      r.providerName(match.Provider) + " key " + match.Redacted + " committed in " + file.path,
		method:     finding.MethodPattern,
		confidence: confidence,
		flags:      flags,
		unproven:   unproven,
		evidence:   []finding.Evidence{r.evidenceAt(file.path, line)},
	})
}

func (r *run) applyCustomRules(file *sourceFile, number int, line string) {
	for _, rule := range r.scanner.customRules {
		pattern := rule.Regexp()
		if !pattern.MatchString(line) {
			continue
		}
		redacted := pattern.ReplaceAllStringFunc(line, secret.Redact)
		excerpt := strings.TrimSpace(redacted)
		if len(excerpt) > maxExcerpt {
			excerpt = excerpt[:maxExcerpt] + "..."
		}
		f := rule.NewFinding(finding.MethodPattern, finding.ConfidenceHigh, finding.Evidence{
			Path:      file.path,
			StartLine: number,
			EndLine:   number,
			Excerpt:   excerpt,
		})
		if _, duplicate := r.seen[f.ID]; duplicate {
			continue
		}
		r.seen[f.ID] = struct{}{}
		r.findings = append(r.findings, f)
	}
}

func containsFlag(flags []finding.Flag, target finding.Flag) bool {
	for _, flag := range flags {
		if flag == target {
			return true
		}
	}
	return false
}
