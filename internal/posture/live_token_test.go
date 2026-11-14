package posture

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ryankshah/jackproof/internal/finding"
	"github.com/ryankshah/jackproof/internal/rules"
)

const testToken = "ya29.test-token-value"

func tokenOptions(t *testing.T, server *httptest.Server) TokenOptions {
	t.Helper()
	ruleSet, err := rules.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	return TokenOptions{
		Token: testToken, Endpoint: server.URL, Rules: ruleSet,
		Now: func() time.Time { return time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC) },
	}
}

func TestCheckVertexLogging(t *testing.T) {
	const all = `{"auditConfigs":[{"service":"allServices","auditLogConfigs":[{"logType":"ADMIN_READ"},{"logType":"DATA_READ"},{"logType":"DATA_WRITE"}]}]}`
	tests := []struct {
		name       string
		state      string
		policy     string
		wantFind   bool
		wantPolicy bool
	}{
		{"enabled without audit configs", "ENABLED", `{}`, true, true},
		{"enabled with full data access logs", "ENABLED", all, false, true},
		{"enabled with vertex specific logs", "ENABLED", `{"auditConfigs":[{"service":"aiplatform.googleapis.com","auditLogConfigs":[{"logType":"DATA_READ"},{"logType":"DATA_WRITE"}]}]}`, false, true},
		{"enabled with reads only", "ENABLED", `{"auditConfigs":[{"service":"allServices","auditLogConfigs":[{"logType":"DATA_READ"}]}]}`, true, true},
		{"enabled with logs for another service", "ENABLED", `{"auditConfigs":[{"service":"storage.googleapis.com","auditLogConfigs":[{"logType":"DATA_READ"},{"logType":"DATA_WRITE"}]}]}`, true, true},
		{"service disabled", "DISABLED", `{}`, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policyCalled := false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer "+testToken {
					t.Errorf("authorization = %q", r.Header.Get("Authorization"))
				}
				switch r.URL.Path {
				case "/v1/projects/my-project/services/aiplatform.googleapis.com":
					if r.Method != http.MethodGet {
						t.Errorf("service state method = %s", r.Method)
					}
					_, _ = io.WriteString(w, `{"state":"`+tt.state+`"}`)
				case "/v1/projects/my-project:getIamPolicy":
					policyCalled = true
					if r.Method != http.MethodPost {
						t.Errorf("policy method = %s", r.Method)
					}
					_, _ = io.WriteString(w, tt.policy)
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()

			findings, err := CheckVertexLogging(context.Background(), "my-project", tokenOptions(t, server))
			if err != nil {
				t.Fatal(err)
			}
			if policyCalled != tt.wantPolicy {
				t.Errorf("policy called = %v, want %v", policyCalled, tt.wantPolicy)
			}
			if (len(findings) == 1) != tt.wantFind || len(findings) > 1 {
				t.Fatalf("findings = %+v", findings)
			}
			if tt.wantFind {
				f := findings[0]
				if err := f.Validate(); err != nil {
					t.Error(err)
				}
				if f.Confidence != finding.ConfidenceMedium || f.Flags[len(f.Flags)-1] != finding.FlagIncomplete || !strings.Contains(strings.Join(f.Unproven, " "), "inherited") {
					t.Errorf("finding = %+v", f)
				}
				if !strings.Contains(f.Remediation, "google_project_iam_audit_config") {
					t.Error("remediation lacks the logging snippet")
				}
			}
		})
	}
}

func TestCheckAzureDiagnostics(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testToken {
			t.Errorf("authorization = %q", r.Header.Get("Authorization"))
		}
		const accountsPath = "/subscriptions/sub-1/providers/Microsoft.CognitiveServices/accounts"
		switch {
		case r.URL.Path == accountsPath && r.URL.Query().Get("page") == "":
			if r.URL.Query().Get("api-version") != "2024-10-01" {
				t.Errorf("accounts api-version = %q", r.URL.Query().Get("api-version"))
			}
			_, _ = io.WriteString(w, `{"value":[{"id":"/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/bare","name":"bare","kind":"OpenAI"},{"id":"/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/speech","name":"speech","kind":"SpeechServices"}],"nextLink":"`+server.URL+accountsPath+`?page=2"}`)
		case r.URL.Path == accountsPath:
			_, _ = io.WriteString(w, `{"value":[{"id":"/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/logged","name":"logged","kind":"openai"}]}`)
		case strings.HasSuffix(r.URL.Path, "/accounts/bare/providers/Microsoft.Insights/diagnosticSettings"):
			if r.URL.Query().Get("api-version") != "2021-05-01-preview" {
				t.Errorf("diagnostics api-version = %q", r.URL.Query().Get("api-version"))
			}
			_, _ = io.WriteString(w, `{"value":[]}`)
		case strings.HasSuffix(r.URL.Path, "/accounts/logged/providers/Microsoft.Insights/diagnosticSettings"):
			_, _ = io.WriteString(w, `{"value":[{"name":"audit"}]}`)
		default:
			t.Errorf("unexpected request %s", r.URL)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	findings, err := CheckAzureDiagnostics(context.Background(), "sub-1", tokenOptions(t, server))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || !strings.Contains(findings[0].Title, "bare") || findings[0].Confidence != finding.ConfidenceHigh {
		t.Fatalf("findings = %+v", findings)
	}
	if err := findings[0].Validate(); err != nil {
		t.Error(err)
	}
	if !strings.Contains(findings[0].Remediation, "azurerm_monitor_diagnostic_setting") {
		t.Error("remediation lacks the logging snippet")
	}
}

func TestTokenChecksHandleErrorsWithoutLeakingTheToken(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		body    string
		wantErr string
	}{
		{"token refused", 403, `{}`, "refused the token"},
		{"expired token", 401, `{}`, "refused the token"},
		{"server error", 500, `{}`, "HTTP 500"},
		{"invalid body", 200, `not json`, "decode"},
	}
	for _, tt := range tests {
		for _, check := range []string{"gcp", "azure"} {
			t.Run(check+" "+tt.name, func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(tt.status)
					_, _ = io.WriteString(w, tt.body)
				}))
				defer server.Close()
				var err error
				if check == "gcp" {
					_, err = CheckVertexLogging(context.Background(), "p", tokenOptions(t, server))
				} else {
					_, err = CheckAzureDiagnostics(context.Background(), "s", tokenOptions(t, server))
				}
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want it to contain %q", err, tt.wantErr)
				}
				if strings.Contains(err.Error(), testToken) {
					t.Errorf("error leaks the token: %v", err)
				}
			})
		}
	}
}

func TestTokenChecksValidateInput(t *testing.T) {
	ruleSet, _ := rules.LoadEmbedded()
	if _, err := CheckVertexLogging(context.Background(), "p", TokenOptions{Rules: ruleSet}); err == nil || !strings.Contains(err.Error(), "access token") {
		t.Errorf("missing token: %v", err)
	}
	if _, err := CheckVertexLogging(context.Background(), "", TokenOptions{Rules: ruleSet, Token: "t"}); err == nil || !strings.Contains(err.Error(), "project") {
		t.Errorf("missing project: %v", err)
	}
	if _, err := CheckAzureDiagnostics(context.Background(), "", TokenOptions{Rules: ruleSet, Token: "t"}); err == nil || !strings.Contains(err.Error(), "subscription") {
		t.Errorf("missing subscription: %v", err)
	}
	empty, _ := rules.Load(emptyFS{})
	if _, err := CheckAzureDiagnostics(context.Background(), "s", TokenOptions{Rules: empty, Token: "t"}); err == nil {
		t.Error("expected an error for a catalogue without the posture rules")
	}
}

func TestTokenCheckConnectionErrorDoesNotLeakTheToken(t *testing.T) {
	ruleSet, _ := rules.LoadEmbedded()
	_, err := CheckVertexLogging(context.Background(), "p", TokenOptions{Rules: ruleSet, Token: testToken, Endpoint: "http://127.0.0.1:1"})
	if err == nil || strings.Contains(err.Error(), testToken) {
		t.Errorf("error = %v", err)
	}
}
