package exposure

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/ryankshah/jackproof/internal/finding"
	"github.com/ryankshah/jackproof/internal/rules"
	"github.com/ryankshah/jackproof/internal/secret"
)

const (
	ruleLive       = "JP-EXP-003"
	userAgent      = "jackproof"
	DefaultTimeout = 10 * time.Second

	StatusAccepted     = "accepted"
	StatusRejected     = "rejected"
	StatusInconclusive = "inconclusive"
	StatusUnsupported  = "unsupported"
)

type Result struct {
	Source      Source `json:"source"`
	Provider    string `json:"provider,omitempty"`
	Redacted    string `json:"redacted,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Status      string `json:"status"`
	Detail      string `json:"detail"`
}

type Verifier struct {
	Client  *http.Client
	Secrets *secret.Catalogue
}

func NewVerifier(secrets *secret.Catalogue, timeout time.Duration) *Verifier {
	return &Verifier{
		Secrets: secrets,
		Client: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (v *Verifier) CheckAll(ctx context.Context, input []byte) ([]Result, error) {
	var results []Result
	scanner := bufio.NewScanner(bytes.NewReader(input))
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		results = append(results, v.Check(ctx, Source{Path: stdinSource, Line: lineNumber}, line))
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read keys: %w", err)
	}
	return results, nil
}

func (v *Verifier) Check(ctx context.Context, source Source, line string) Result {
	result := Result{Source: source}
	matches := v.Secrets.Detect(line)
	if len(matches) != 1 {
		result.Status = StatusUnsupported
		result.Detail = "the provider could not be identified from this line. Pass context-only keys as NAME=value, for example MISTRAL_API_KEY=value."
		return result
	}
	match := matches[0]
	result.Provider = match.Provider
	result.Redacted = match.Redacted
	result.Fingerprint = match.Fingerprint

	provider, _ := v.Secrets.Provider(match.Provider)
	if provider.Verify == nil {
		result.Status = StatusUnsupported
		result.Detail = fmt.Sprintf("no read-only check is defined for %s. Revoke the key at the provider and confirm there.", provider.Name)
		return result
	}
	status, detail := v.request(ctx, provider.Verify, line[match.Start:match.End])
	result.Status = status
	result.Detail = detail
	return result
}

func (v *Verifier) request(ctx context.Context, spec *secret.VerifySpec, key string) (string, string) {
	target := spec.URL
	auth := spec.Auth
	if name, found := strings.CutPrefix(auth, "query:"); found {
		target += "?" + url.Values{name: {key}}.Encode()
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return StatusInconclusive, "the request could not be built"
	}
	request.Header.Set("User-Agent", userAgent)
	for name, value := range spec.Headers {
		request.Header.Set(name, value)
	}
	switch {
	case auth == "bearer":
		request.Header.Set("Authorization", "Bearer "+key)
	case strings.HasPrefix(auth, "header:"):
		request.Header.Set(strings.TrimPrefix(auth, "header:"), key)
	}
	response, err := v.Client.Do(request)
	if err != nil {
		return StatusInconclusive, "the request failed: " + safeError(err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<16))
		_ = response.Body.Close()
	}()
	return classify(spec, response.StatusCode)
}

func classify(spec *secret.VerifySpec, code int) (string, string) {
	rejected := spec.Rejected
	if len(rejected) == 0 {
		rejected = []int{http.StatusUnauthorized}
	}
	switch {
	case code >= 200 && code < 300:
		return StatusAccepted, fmt.Sprintf("the provider accepted the key (HTTP %d)", code)
	case slices.Contains(rejected, code):
		return StatusRejected, fmt.Sprintf("the provider rejected the key (HTTP %d)", code)
	case code == http.StatusForbidden:
		return StatusInconclusive, "HTTP 403: the key may be valid with restricted permissions"
	}
	return StatusInconclusive, fmt.Sprintf("HTTP %d does not show whether the key is valid", code)
}

func safeError(err error) string {
	for {
		var urlErr *url.Error
		if !errors.As(err, &urlErr) {
			return err.Error()
		}
		err = urlErr.Err
	}
}

func ResultFindings(results []Result, ruleSet *rules.Catalogue) ([]finding.Finding, error) {
	rule, ok := ruleSet.Get(ruleLive)
	if !ok {
		return nil, fmt.Errorf("rule catalogue is missing %s", ruleLive)
	}
	var findings []finding.Finding
	for _, result := range results {
		if result.Status != StatusAccepted {
			continue
		}
		f := rule.NewFinding(finding.MethodPattern, finding.ConfidenceHigh, finding.Evidence{
			Path:      result.Source.Path,
			StartLine: result.Source.Line,
			EndLine:   result.Source.Line,
			Excerpt:   fmt.Sprintf("%s key %s (fingerprint %s)", result.Provider, result.Redacted, result.Fingerprint),
		})
		f.Title = fmt.Sprintf("%s key %s still authenticates", result.Provider, result.Redacted)
		findings = append(findings, f)
	}
	return findings, nil
}

func AllRejected(results []Result) bool {
	for _, result := range results {
		if result.Status != StatusRejected {
			return false
		}
	}
	return len(results) > 0
}

func ResultsText(results []Result) string {
	var builder strings.Builder
	for _, result := range results {
		label := result.Provider
		if label == "" {
			label = "unknown provider"
		}
		fmt.Fprintf(&builder, "line %d: %s %s fingerprint %s: %s: %s\n", result.Source.Line, label, result.Redacted, result.Fingerprint, result.Status, result.Detail)
	}
	builder.WriteString("\nDeleting a stored secret does not revoke it. Only a rejected result shows that a credential is dead. An inconclusive or unsupported result does not.\n")
	return builder.String()
}
