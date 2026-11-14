package posture

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ryankshah/jackproof/internal/finding"
	"github.com/ryankshah/jackproof/internal/rules"
)

const (
	GoogleTokenVariable = "GOOGLE_OAUTH_ACCESS_TOKEN"
	AzureTokenVariable  = "AZURE_ACCESS_TOKEN"

	googleServiceUsage     = "https://serviceusage.googleapis.com"
	googleResourceManager  = "https://cloudresourcemanager.googleapis.com"
	azureResourceManager   = "https://management.azure.com"
	azureAccountsVersion   = "2024-10-01"
	azureDiagnosticVersion = "2021-05-01-preview"
	maxAzurePages          = 10
)

type TokenOptions struct {
	Token    string
	Endpoint string
	Client   *http.Client
	Now      func() time.Time
	Rules    *rules.Catalogue
}

func (o *TokenOptions) prepare() (*rules.Rule, error) {
	rule, ok := o.Rules.Get(ruleLogging)
	if !ok {
		return nil, fmt.Errorf("rule catalogue is missing %s", ruleLogging)
	}
	if o.Token == "" {
		return nil, errors.New("live mode needs an access token")
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Client == nil {
		o.Client = &http.Client{Timeout: liveTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	return &rule, nil
}

func (o TokenOptions) call(ctx context.Context, method, target string, body []byte) ([]byte, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+o.Token)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := o.Client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("call %s: %w", request.URL.Host, unwrapURLError(err))
	}
	defer func() { _ = response.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(response.Body, maxLiveBody))
	if err != nil {
		return nil, fmt.Errorf("read the response from %s: %w", request.URL.Host, err)
	}
	switch {
	case response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden:
		return nil, fmt.Errorf("%s refused the token (HTTP %d). It may have expired or lack read access", request.URL.Host, response.StatusCode)
	case response.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("%s answered HTTP %d", request.URL.Host, response.StatusCode)
	}
	return data, nil
}

func (o TokenOptions) base(defaultBase string) string {
	if o.Endpoint != "" {
		return strings.TrimRight(o.Endpoint, "/")
	}
	return defaultBase
}

func (o TokenOptions) finding(rule *rules.Rule, record, title string, confidence finding.Confidence, flags []finding.Flag, unproven []string, snippet string) finding.Finding {
	f := rule.NewFinding(finding.MethodPolicyEval, confidence, finding.Evidence{
		Record: record, Timestamp: o.Now().UTC(), Excerpt: title,
	})
	f.Title = title
	f.Flags = append(f.Flags, flags...)
	f.Unproven = unproven
	f.Remediation = rule.Remediation + "\n\n" + snippet
	return f
}

type serviceState struct {
	State string `json:"state"`
}

type projectPolicy struct {
	AuditConfigs []struct {
		Service         string `json:"service"`
		AuditLogConfigs []struct {
			LogType string `json:"logType"`
		} `json:"auditLogConfigs"`
	} `json:"auditConfigs"`
}

func CheckVertexLogging(ctx context.Context, project string, options TokenOptions) ([]finding.Finding, error) {
	rule, err := options.prepare()
	if err != nil {
		return nil, err
	}
	if project == "" {
		return nil, errors.New("live mode needs a Google Cloud project")
	}
	escaped := url.PathEscape(project)
	data, err := options.call(ctx, http.MethodGet, fmt.Sprintf("%s/v1/projects/%s/services/%s", options.base(googleServiceUsage), escaped, vertexService), nil)
	if err != nil {
		return nil, fmt.Errorf("read the Vertex AI service state: %w", err)
	}
	var state serviceState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("decode the service state: %w", err)
	}
	if state.State != "ENABLED" {
		return nil, nil
	}

	data, err = options.call(ctx, http.MethodPost, fmt.Sprintf("%s/v1/projects/%s:getIamPolicy", options.base(googleResourceManager), escaped), []byte("{}"))
	if err != nil {
		return nil, fmt.Errorf("read the project policy: %w", err)
	}
	var policy projectPolicy
	if err := json.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("decode the project policy: %w", err)
	}
	for _, config := range policy.AuditConfigs {
		if config.Service != "allServices" && config.Service != vertexService {
			continue
		}
		types := make(map[string]bool)
		for _, logConfig := range config.AuditLogConfigs {
			types[logConfig.LogType] = true
		}
		if types["DATA_READ"] && types["DATA_WRITE"] {
			return nil, nil
		}
	}
	title := fmt.Sprintf("Vertex AI is enabled in project %s and its project policy has no Data Access audit logs for it", project)
	return []finding.Finding{options.finding(rule, "gcp:"+project+":getIamPolicy", title, finding.ConfidenceMedium,
		[]finding.Flag{finding.FlagIncomplete},
		[]string{"Audit settings inherited from a folder or the organization are not part of the project policy and were not read."},
		gcpLoggingSnippet)}, nil
}

type azureAccounts struct {
	Value []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Kind string `json:"kind"`
	} `json:"value"`
	NextLink string `json:"nextLink"`
}

type azureDiagnostics struct {
	Value []json.RawMessage `json:"value"`
}

func CheckAzureDiagnostics(ctx context.Context, subscription string, options TokenOptions) ([]finding.Finding, error) {
	rule, err := options.prepare()
	if err != nil {
		return nil, err
	}
	if subscription == "" {
		return nil, errors.New("live mode needs an Azure subscription id")
	}
	base := options.base(azureResourceManager)
	next := fmt.Sprintf("%s/subscriptions/%s/providers/Microsoft.CognitiveServices/accounts?api-version=%s", base, url.PathEscape(subscription), azureAccountsVersion)
	var findings []finding.Finding
	for page := 0; next != "" && page < maxAzurePages; page++ {
		data, err := options.call(ctx, http.MethodGet, next, nil)
		if err != nil {
			return nil, fmt.Errorf("list Azure OpenAI accounts: %w", err)
		}
		var accounts azureAccounts
		if err := json.Unmarshal(data, &accounts); err != nil {
			return nil, fmt.Errorf("decode the account list: %w", err)
		}
		for _, account := range accounts.Value {
			if !strings.EqualFold(account.Kind, "OpenAI") {
				continue
			}
			diagnostics, err := options.call(ctx, http.MethodGet, fmt.Sprintf("%s%s/providers/Microsoft.Insights/diagnosticSettings?api-version=%s", base, account.ID, azureDiagnosticVersion), nil)
			if err != nil {
				return nil, fmt.Errorf("read the diagnostic settings of %s: %w", account.Name, err)
			}
			var settings azureDiagnostics
			if err := json.Unmarshal(diagnostics, &settings); err != nil {
				return nil, fmt.Errorf("decode the diagnostic settings of %s: %w", account.Name, err)
			}
			if len(settings.Value) == 0 {
				title := fmt.Sprintf("Azure OpenAI account %s has no diagnostic setting", account.Name)
				findings = append(findings, options.finding(rule, "azure:"+account.ID, title, finding.ConfidenceHigh, nil,
					[]string{"Other subscriptions were not checked."}, azureLoggingSnippet))
			}
		}
		next = accounts.NextLink
	}
	return findings, nil
}
