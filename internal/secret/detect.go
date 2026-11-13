package secret

import (
	"sort"
	"strings"

	"github.com/ryankshah/jackproof/internal/finding"
)

const minDistinctContextChars = 8

type Match struct {
	Provider    string
	Format      string
	Start       int
	End         int
	Redacted    string
	Fingerprint string
	Confidence  finding.Confidence
	Verified    bool
}

func (c *Catalogue) Detect(line string) []Match {
	var matches []Match
	for _, compiled := range c.compiled {
		for _, span := range compiled.re.FindAllStringSubmatchIndex(line, -1) {
			start, end := span[2], span[3]
			value := line[start:end]
			if compiled.format.Context && !plausibleContextValue(value) {
				continue
			}
			confidence := finding.ConfidenceHigh
			if compiled.format.Context {
				confidence = finding.ConfidenceMedium
			}
			matches = append(matches, Match{
				Provider:    compiled.provider.ID,
				Format:      compiled.format.Name,
				Start:       start,
				End:         end,
				Redacted:    Redact(value),
				Fingerprint: Fingerprint(value),
				Confidence:  confidence,
				Verified:    compiled.format.Verified,
			})
		}
	}
	return resolveOverlaps(matches)
}

func (c *Catalogue) RedactLine(line string) string {
	matches := c.Detect(line)
	if len(matches) == 0 {
		return line
	}
	var builder strings.Builder
	cursor := 0
	for _, match := range matches {
		builder.WriteString(line[cursor:match.Start])
		builder.WriteString(match.Redacted)
		cursor = match.End
	}
	builder.WriteString(line[cursor:])
	return builder.String()
}

func plausibleContextValue(value string) bool {
	distinct := make(map[rune]struct{})
	for _, r := range value {
		distinct[r] = struct{}{}
	}
	return len(distinct) >= minDistinctContextChars
}

func resolveOverlaps(matches []Match) []Match {
	sort.SliceStable(matches, func(i, j int) bool {
		a, b := matches[i], matches[j]
		if a.Confidence != b.Confidence {
			return a.Confidence.AtLeast(b.Confidence)
		}
		return a.End-a.Start > b.End-b.Start
	})
	var kept []Match
	for _, candidate := range matches {
		if !overlapsAny(candidate, kept) {
			kept = append(kept, candidate)
		}
	}
	sort.Slice(kept, func(i, j int) bool { return kept[i].Start < kept[j].Start })
	return kept
}

func overlapsAny(candidate Match, others []Match) bool {
	for _, other := range others {
		if candidate.Start < other.End && other.Start < candidate.End {
			return true
		}
	}
	return false
}
