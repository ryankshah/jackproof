package posture

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/ryankshah/jackproof/internal/finding"
	"github.com/ryankshah/jackproof/internal/rules"
)

const (
	loggingPath    = "/logging/modelinvocations"
	loggingService = "bedrock"
	liveTimeout    = 15 * time.Second
	maxLiveBody    = 1 << 20
	emptyPayload   = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
}

func CredentialsFromEnvironment() (Credentials, error) {
	credentials := Credentials{
		AccessKeyID:     os.Getenv("AWS_ACCESS_KEY_ID"),
		SecretAccessKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
		SessionToken:    os.Getenv("AWS_SESSION_TOKEN"),
	}
	if credentials.AccessKeyID == "" || credentials.SecretAccessKey == "" {
		return Credentials{}, errors.New("live mode needs AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY in the environment")
	}
	return credentials, nil
}

func RegionFromEnvironment() string {
	for _, name := range []string{"AWS_REGION", "AWS_DEFAULT_REGION"} {
		if region := os.Getenv(name); region != "" {
			return region
		}
	}
	return ""
}

type LiveOptions struct {
	Region      string
	Credentials Credentials
	Endpoint    string
	Client      *http.Client
	Now         func() time.Time
	Rules       *rules.Catalogue
}

type loggingResponse struct {
	LoggingConfig *struct {
		TextDataDeliveryEnabled      *bool `json:"textDataDeliveryEnabled"`
		ImageDataDeliveryEnabled     *bool `json:"imageDataDeliveryEnabled"`
		EmbeddingDataDeliveryEnabled *bool `json:"embeddingDataDeliveryEnabled"`
	} `json:"loggingConfig"`
}

func CheckBedrockLogging(ctx context.Context, options LiveOptions) ([]finding.Finding, error) {
	rule, ok := options.Rules.Get(ruleLogging)
	if !ok {
		return nil, fmt.Errorf("rule catalogue is missing %s", ruleLogging)
	}
	if options.Region == "" {
		return nil, errors.New("live mode needs a region: pass --region or set AWS_REGION")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Client == nil {
		options.Client = &http.Client{Timeout: liveTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	endpoint := options.Endpoint
	if endpoint == "" {
		endpoint = fmt.Sprintf("https://%s.%s.amazonaws.com", loggingService, options.Region)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+loggingPath, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	signRequest(request, options.Credentials, options.Region, loggingService, options.Now())
	response, err := options.Client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("call the Bedrock API in %s: %w", options.Region, unwrapURLError(err))
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxLiveBody))
	if err != nil {
		return nil, fmt.Errorf("read the Bedrock response: %w", err)
	}
	switch {
	case response.StatusCode == http.StatusForbidden || response.StatusCode == http.StatusUnauthorized:
		return nil, fmt.Errorf("the credentials cannot call bedrock:GetModelInvocationLoggingConfiguration in %s (HTTP %d)", options.Region, response.StatusCode)
	case response.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("the Bedrock API answered HTTP %d in %s", response.StatusCode, options.Region)
	}
	var parsed loggingResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("decode the Bedrock response: %w", err)
	}

	var title string
	switch {
	case parsed.LoggingConfig == nil:
		title = fmt.Sprintf("Bedrock model invocation logging is not configured in %s", options.Region)
	case allDisabled(parsed):
		title = fmt.Sprintf("Bedrock model invocation logging delivers nothing in %s", options.Region)
	default:
		return nil, nil
	}
	when := options.Now().UTC()
	evidence := finding.Evidence{
		Record:    fmt.Sprintf("aws:%s:%s:GetModelInvocationLoggingConfiguration", loggingService, options.Region),
		Timestamp: when,
		Excerpt:   title,
	}
	f := rule.NewFinding(finding.MethodPolicyEval, finding.ConfidenceHigh, evidence)
	f.Title = title
	f.Unproven = []string{"Other regions were not checked."}
	f.Remediation = rule.Remediation + "\n\n" + awsLoggingSnippet
	return []finding.Finding{f}, nil
}

func allDisabled(response loggingResponse) bool {
	config := response.LoggingConfig
	for _, enabled := range []*bool{config.TextDataDeliveryEnabled, config.ImageDataDeliveryEnabled, config.EmbeddingDataDeliveryEnabled} {
		if enabled == nil || *enabled {
			return false
		}
	}
	return true
}

func unwrapURLError(err error) error {
	for {
		var urlErr *url.Error
		if !errors.As(err, &urlErr) {
			return err
		}
		err = urlErr.Err
	}
}

func signRequest(request *http.Request, credentials Credentials, region, service string, now time.Time) {
	now = now.UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")

	request.Header.Set("X-Amz-Date", amzDate)
	if credentials.SessionToken != "" {
		request.Header.Set("X-Amz-Security-Token", credentials.SessionToken)
	}
	signedHeaders := "host;x-amz-date"
	canonicalHeaders := "host:" + request.URL.Host + "\n" + "x-amz-date:" + amzDate + "\n"
	if credentials.SessionToken != "" {
		signedHeaders += ";x-amz-security-token"
		canonicalHeaders += "x-amz-security-token:" + credentials.SessionToken + "\n"
	}
	canonicalRequest := strings.Join([]string{
		request.Method, request.URL.EscapedPath(), request.URL.RawQuery, canonicalHeaders, signedHeaders, emptyPayload,
	}, "\n")

	scope := strings.Join([]string{dateStamp, region, service, "aws4_request"}, "/")
	digest := sha256.Sum256([]byte(canonicalRequest))
	stringToSign := strings.Join([]string{"AWS4-HMAC-SHA256", amzDate, scope, hex.EncodeToString(digest[:])}, "\n")

	key := hmacSHA256([]byte("AWS4"+credentials.SecretAccessKey), dateStamp)
	key = hmacSHA256(key, region)
	key = hmacSHA256(key, service)
	key = hmacSHA256(key, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(key, stringToSign))

	request.Header.Set("Authorization", fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		credentials.AccessKeyID, scope, signedHeaders, signature))
}

func hmacSHA256(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return mac.Sum(nil)
}
