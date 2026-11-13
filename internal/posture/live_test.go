package posture

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ryankshah/jackproof/internal/rules"
)

func TestSignRequestMatchesTheDocumentedTestVector(t *testing.T) {
	request, err := http.NewRequest(http.MethodGet, "https://example.amazonaws.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	credentials := Credentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"}
	signRequest(request, credentials, "us-east-1", "service", time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC))

	want := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
	if got := request.Header.Get("Authorization"); got != want {
		t.Errorf("authorization = %s\nwant          %s", got, want)
	}
	if request.Header.Get("X-Amz-Date") != "20150830T123600Z" {
		t.Errorf("date = %s", request.Header.Get("X-Amz-Date"))
	}
}

func TestSignRequestIncludesTheSessionToken(t *testing.T) {
	request, _ := http.NewRequest(http.MethodGet, "https://bedrock.us-east-1.amazonaws.com/logging/modelinvocations", nil)
	signRequest(request, Credentials{AccessKeyID: "ASIAEXAMPLE", SecretAccessKey: "secret", SessionToken: "token"}, "us-east-1", "bedrock", time.Unix(0, 0))
	authorization := request.Header.Get("Authorization")
	if !strings.Contains(authorization, "SignedHeaders=host;x-amz-date;x-amz-security-token") || request.Header.Get("X-Amz-Security-Token") != "token" {
		t.Errorf("authorization = %s, token header = %q", authorization, request.Header.Get("X-Amz-Security-Token"))
	}
	if strings.Contains(authorization, "secret") {
		t.Error("the authorization header contains the secret key")
	}
}

func liveOptions(t *testing.T, server *httptest.Server) LiveOptions {
	t.Helper()
	ruleSet, err := rules.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	return LiveOptions{
		Region:      "us-east-1",
		Credentials: Credentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"},
		Endpoint:    server.URL,
		Now:         func() time.Time { return time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC) },
		Rules:       ruleSet,
	}
}

func TestCheckBedrockLogging(t *testing.T) {
	tests := []struct {
		name      string
		status    int
		body      string
		wantTitle string
		wantNone  bool
		wantErr   string
	}{
		{"not configured", 200, `{}`, "is not configured in us-east-1", false, ""},
		{"null configuration", 200, `{"loggingConfig": null}`, "is not configured in us-east-1", false, ""},
		{"all delivery disabled", 200, `{"loggingConfig": {"textDataDeliveryEnabled": false, "imageDataDeliveryEnabled": false, "embeddingDataDeliveryEnabled": false}}`, "delivers nothing in us-east-1", false, ""},
		{"logging on", 200, `{"loggingConfig": {"textDataDeliveryEnabled": true, "imageDataDeliveryEnabled": false, "embeddingDataDeliveryEnabled": false}}`, "", true, ""},
		{"delivery unspecified", 200, `{"loggingConfig": {"s3Config": {}}}`, "", true, ""},
		{"access denied", 403, `{"message": "denied"}`, "", false, "cannot call bedrock:GetModelInvocationLoggingConfiguration"},
		{"server error", 500, `{}`, "", false, "HTTP 500"},
		{"invalid body", 200, `not json`, "", false, "decode the Bedrock response"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var seen *http.Request
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen = r
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()

			findings, err := CheckBedrockLogging(context.Background(), liveOptions(t, server))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if seen.Method != http.MethodGet || seen.URL.Path != "/logging/modelinvocations" || !strings.HasPrefix(seen.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
				t.Errorf("request = %s %s %v", seen.Method, seen.URL.Path, seen.Header)
			}
			if tt.wantNone {
				if len(findings) != 0 {
					t.Errorf("findings = %+v", findings)
				}
				return
			}
			if len(findings) != 1 || findings[0].Rule != "JP-POS-003" || !strings.Contains(findings[0].Title, tt.wantTitle) {
				t.Fatalf("findings = %+v", findings)
			}
			if err := findings[0].Validate(); err != nil {
				t.Error(err)
			}
			if len(findings[0].Unproven) == 0 || !strings.Contains(findings[0].Remediation, "aws_bedrock_model_invocation_logging_configuration") {
				t.Errorf("finding = %+v", findings[0])
			}
		})
	}
}

func TestCheckBedrockLoggingValidatesItsInput(t *testing.T) {
	ruleSet, err := rules.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CheckBedrockLogging(context.Background(), LiveOptions{Rules: ruleSet}); err == nil || !strings.Contains(err.Error(), "needs a region") {
		t.Errorf("missing region: %v", err)
	}
	empty, err := rules.Load(emptyFS{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CheckBedrockLogging(context.Background(), LiveOptions{Region: "us-east-1", Rules: empty}); err == nil {
		t.Error("expected an error for a catalogue without the posture rules")
	}
}

func TestCheckBedrockLoggingDoesNotLeakCredentialsInErrors(t *testing.T) {
	ruleSet, _ := rules.LoadEmbedded()
	options := LiveOptions{
		Region: "us-east-1", Rules: ruleSet, Endpoint: "http://127.0.0.1:1",
		Credentials: Credentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "super-secret-value"},
	}
	_, err := CheckBedrockLogging(context.Background(), options)
	if err == nil {
		t.Fatal("expected a connection error")
	}
	if strings.Contains(err.Error(), "super-secret-value") || strings.Contains(err.Error(), "AKIDEXAMPLE") {
		t.Errorf("error leaks credentials: %v", err)
	}
}

func TestCredentialsAndRegionFromEnvironment(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	if _, err := CredentialsFromEnvironment(); err == nil {
		t.Error("expected an error without credentials")
	}
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDEXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	t.Setenv("AWS_SESSION_TOKEN", "token")
	credentials, err := CredentialsFromEnvironment()
	if err != nil || credentials.SessionToken != "token" {
		t.Errorf("credentials = %+v, err = %v", credentials, err)
	}

	t.Setenv("AWS_REGION", "")
	t.Setenv("AWS_DEFAULT_REGION", "eu-west-1")
	if RegionFromEnvironment() != "eu-west-1" {
		t.Errorf("region = %q", RegionFromEnvironment())
	}
	t.Setenv("AWS_REGION", "us-west-2")
	if RegionFromEnvironment() != "us-west-2" {
		t.Errorf("region = %q", RegionFromEnvironment())
	}
}
