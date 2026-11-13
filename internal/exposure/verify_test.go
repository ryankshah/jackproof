package exposure

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ryankshah/jackproof/internal/finding"
	"github.com/ryankshah/jackproof/internal/rules"
	"github.com/ryankshah/jackproof/internal/secret"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func reply(status int) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader("{}")), Header: make(http.Header)}
}

func testVerifier(t *testing.T, handler roundTripFunc) *Verifier {
	t.Helper()
	secrets, err := secret.LoadCatalogue()
	if err != nil {
		t.Fatal(err)
	}
	verifier := NewVerifier(secrets, time.Second)
	verifier.Client.Transport = handler
	return verifier
}

func TestCheckRequestsPerProvider(t *testing.T) {
	openaiKey := "sk-" + strings.Repeat("b", 48)
	anthropicKey := "sk-" + "ant-" + strings.Repeat("x", 40)
	googleKey := "AI" + "za" + strings.Repeat("c", 35)
	mistralValue := "abcdefghijklmnopqrstuvwxyz012345"

	tests := []struct {
		name       string
		line       string
		check      func(t *testing.T, request *http.Request)
		wantProv   string
		wantStatus int
	}{
		{
			name: "bearer", line: openaiKey, wantProv: "openai", wantStatus: 200,
			check: func(t *testing.T, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer "+openaiKey || r.Host != "api.openai.com" || r.Method != http.MethodGet {
					t.Errorf("request = %s %s %v", r.Method, r.URL, r.Header)
				}
			},
		},
		{
			name: "header with version", line: anthropicKey, wantProv: "anthropic", wantStatus: 200,
			check: func(t *testing.T, r *http.Request) {
				if r.Header.Get("x-api-key") != anthropicKey || r.Header.Get("anthropic-version") == "" {
					t.Errorf("headers = %v", r.Header)
				}
			},
		},
		{
			name: "query parameter", line: googleKey, wantProv: "google-ai-studio", wantStatus: 200,
			check: func(t *testing.T, r *http.Request) {
				if r.URL.Query().Get("key") != googleKey || r.Header.Get("Authorization") != "" {
					t.Errorf("url = %s, headers = %v", r.URL, r.Header)
				}
			},
		},
		{
			name: "context only key", line: "MISTRAL_API_KEY=" + mistralValue, wantProv: "mistral", wantStatus: 200,
			check: func(t *testing.T, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer "+mistralValue {
					t.Errorf("authorization = %q", r.Header.Get("Authorization"))
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifier := testVerifier(t, func(r *http.Request) (*http.Response, error) {
				tt.check(t, r)
				return reply(tt.wantStatus), nil
			})
			result := verifier.Check(context.Background(), Source{Path: "stdin", Line: 1}, tt.line)
			if result.Provider != tt.wantProv || result.Status != StatusAccepted {
				t.Errorf("result = %+v", result)
			}
			if strings.Contains(result.Redacted+result.Detail+result.Fingerprint, tt.line) {
				t.Error("result contains the full key")
			}
		})
	}
}

func TestCheckClassifiesResponses(t *testing.T) {
	key := "sk-" + strings.Repeat("b", 48)
	googleKey := "AI" + "za" + strings.Repeat("c", 35)
	tests := []struct {
		name   string
		line   string
		status int
		want   string
	}{
		{"ok", key, 200, StatusAccepted},
		{"created", key, 204, StatusAccepted},
		{"unauthorized", key, 401, StatusRejected},
		{"forbidden may be a restricted key", key, 403, StatusInconclusive},
		{"rate limited", key, 429, StatusInconclusive},
		{"server error", key, 503, StatusInconclusive},
		{"redirect is not followed", key, 302, StatusInconclusive},
		{"bad request is not rejection by default", key, 400, StatusInconclusive},
		{"provider specific rejection", googleKey, 400, StatusRejected},
		{"unauthorized is not rejection for google", googleKey, 401, StatusInconclusive},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifier := testVerifier(t, func(*http.Request) (*http.Response, error) { return reply(tt.status), nil })
			result := verifier.Check(context.Background(), Source{Path: "stdin", Line: 1}, tt.line)
			if result.Status != tt.want {
				t.Errorf("status = %s (%s), want %s", result.Status, result.Detail, tt.want)
			}
		})
	}
}

func TestCheckNetworkErrorDoesNotLeakTheKey(t *testing.T) {
	googleKey := "AI" + "za" + strings.Repeat("c", 35)
	verifier := testVerifier(t, func(r *http.Request) (*http.Response, error) {
		return nil, &url.Error{Op: "Get", URL: r.URL.String(), Err: errors.New("connection refused")}
	})
	result := verifier.Check(context.Background(), Source{Path: "stdin", Line: 1}, googleKey)
	if result.Status != StatusInconclusive {
		t.Errorf("status = %s", result.Status)
	}
	if strings.Contains(result.Detail, googleKey) || !strings.Contains(result.Detail, "connection refused") {
		t.Errorf("detail = %q", result.Detail)
	}
}

func TestCheckUnsupportedLines(t *testing.T) {
	perplexity := "pplx" + "-" + strings.Repeat("j", 40)
	tests := []struct {
		name string
		line string
		want string
	}{
		{"no verification endpoint", perplexity, "no read-only check"},
		{"unidentified", "not a key at all", "could not be identified"},
		{"two keys", "sk-" + strings.Repeat("b", 48) + " sk-" + strings.Repeat("c", 48), "could not be identified"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called := false
			verifier := testVerifier(t, func(*http.Request) (*http.Response, error) {
				called = true
				return reply(200), nil
			})
			result := verifier.Check(context.Background(), Source{Path: "stdin", Line: 3}, tt.line)
			if result.Status != StatusUnsupported || !strings.Contains(result.Detail, tt.want) {
				t.Errorf("result = %+v", result)
			}
			if called {
				t.Error("an unsupported line must not cause a request")
			}
		})
	}
}

func TestCheckAllAndHelpers(t *testing.T) {
	good := "sk-" + strings.Repeat("b", 48)
	dead := "sk-" + strings.Repeat("d", 48)
	verifier := testVerifier(t, func(r *http.Request) (*http.Response, error) {
		if strings.Contains(r.Header.Get("Authorization"), strings.Repeat("d", 48)) {
			return reply(401), nil
		}
		return reply(200), nil
	})
	results, err := verifier.CheckAll(context.Background(), []byte(good+"\n\n"+dead+"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 || results[0].Source.Line != 1 || results[1].Source.Line != 3 {
		t.Fatalf("results = %+v", results)
	}
	if results[0].Status != StatusAccepted || results[1].Status != StatusRejected {
		t.Errorf("statuses = %s, %s", results[0].Status, results[1].Status)
	}
	if AllRejected(results) || AllRejected(nil) || !AllRejected(results[1:]) {
		t.Error("AllRejected gave the wrong answer")
	}

	ruleSet, err := rules.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	findings, err := ResultFindings(results, ruleSet)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Rule != "JP-EXP-003" || findings[0].Severity != finding.SeverityCritical {
		t.Fatalf("findings = %+v", findings)
	}
	if err := findings[0].Validate(); err != nil {
		t.Error(err)
	}
	if strings.Contains(findings[0].Title+findings[0].Evidence[0].Excerpt, good) {
		t.Error("finding contains the full key")
	}

	text := ResultsText(results)
	for _, want := range []string{"line 1:", "accepted", "rejected", "Deleting a stored secret does not revoke it"} {
		if !strings.Contains(text, want) {
			t.Errorf("text lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, good) || strings.Contains(text, dead) {
		t.Error("text contains a full key")
	}
}

func TestResultFindingsRequiresRule(t *testing.T) {
	empty, err := rules.Load(emptyFS{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ResultFindings(nil, empty); err == nil {
		t.Error("expected an error")
	}
}

func TestProviderVerifySpecsAreWellFormed(t *testing.T) {
	secrets, err := secret.LoadCatalogue()
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, provider := range secrets.Providers() {
		if provider.Verify == nil {
			continue
		}
		count++
	}
	if count < 10 {
		t.Errorf("only %d providers have a verify spec", count)
	}
}
