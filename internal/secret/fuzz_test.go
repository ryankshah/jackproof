package secret

import (
	"reflect"
	"strings"
	"testing"
)

func FuzzDetect(f *testing.F) {
	catalogue, err := LoadCatalogue()
	if err != nil {
		f.Fatal(err)
	}
	for _, fixture := range positiveFixtures() {
		f.Add(fixture.line)
	}
	for _, fixture := range negativeFixtures() {
		f.Add(fixture.line)
	}
	f.Fuzz(func(t *testing.T, line string) {
		matches := catalogue.Detect(line)
		if !isASCII(line) {
			return
		}
		if unfiltered := catalogue.detect(line, false); !reflect.DeepEqual(matches, unfiltered) {
			t.Fatalf("the prefilter changed the result for %q:\nfiltered   %+v\nunfiltered %+v", line, matches, unfiltered)
		}
		previousEnd := 0
		for _, match := range matches {
			if match.Start < previousEnd || match.End < match.Start || match.End > len(line) {
				t.Fatalf("bad span %d-%d in %q after %d", match.Start, match.End, line, previousEnd)
			}
			previousEnd = match.End
			value := line[match.Start:match.End]
			if match.Fingerprint != Fingerprint(value) {
				t.Fatalf("fingerprint does not match the span %q", value)
			}
			if len(value) >= minRedactable && strings.Contains(match.Redacted, value) {
				t.Fatalf("the redacted form %q contains the whole value", match.Redacted)
			}
		}
		redacted := catalogue.RedactLine(line)
		for _, match := range matches {
			if len(line[match.Start:match.End]) >= minRedactable && len(matches) == 1 && strings.Count(line, line[match.Start:match.End]) == 1 && strings.Contains(redacted, line[match.Start:match.End]) {
				t.Fatalf("RedactLine left a secret in %q", redacted)
			}
		}
	})
}

func isASCII(text string) bool {
	for i := 0; i < len(text); i++ {
		if text[i] >= 0x80 {
			return false
		}
	}
	return true
}

func FuzzRedactAndNormalize(f *testing.F) {
	f.Add("sk-abcdefghijklmnop")
	f.Add("")
	f.Add("ba7816bf8f01cfea")
	f.Fuzz(func(t *testing.T, value string) {
		redacted := Redact(value)
		if len(value) >= minRedactable && len(redacted) >= len(value) {
			t.Fatalf("Redact(%q) = %q is not shorter than the value", value, redacted)
		}
		if len(value) < minRedactable && redacted != redactedFully {
			t.Fatalf("a short value must be fully redacted, got %q", redacted)
		}
		if got := Fingerprint(value); len(got) != fingerprintLength {
			t.Fatalf("fingerprint %q has length %d", got, len(got))
		}
		for _, algorithm := range Algorithms() {
			if normalized, err := NormalizeDigest(algorithm, value); err == nil && normalized != strings.ToLower(strings.TrimSpace(normalized)) {
				t.Fatalf("%s: %q is not normalised", algorithm, normalized)
			}
		}
	})
}
