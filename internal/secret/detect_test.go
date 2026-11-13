package secret

import (
	"strings"
	"testing"

	"github.com/ryankshah/jackproof/internal/finding"
)

const (
	alnum32 = "abcdefghijklmnopqrstuvwxyz012345"
	alnum40 = alnum32 + "6789abcd"
	hex32   = "0123456789abcdef0123456789abcdef"
)

type fixture struct {
	name       string
	line       string
	secret     string
	provider   string
	format     string
	confidence finding.Confidence
}

func positiveFixtures() []fixture {
	anthropicKey := "sk-" + "ant-" + strings.Repeat("x", 90)
	openaiProject := "sk-" + "proj-" + strings.Repeat("a", 30)
	openaiLegacy := "sk-" + strings.Repeat("b", 48)
	googleKey := "AI" + "za" + strings.Repeat("c", 35)
	fireworksKey := "fw" + "_" + strings.Repeat("d", 24)
	groqKey := "gsk" + "_" + strings.Repeat("e", 50)
	openrouterKey := "sk-" + "or-v1-" + strings.Repeat("f", 64)
	xaiKey := "xai" + "-" + strings.Repeat("g", 50)
	hfKey := "hf" + "_" + strings.Repeat("h", 34)
	replicateKey := "r8" + "_" + strings.Repeat("i", 34)
	perplexityKey := "pplx" + "-" + strings.Repeat("j", 40)
	awsKeyID := "AK" + "IA" + strings.Repeat("A", 16)
	awsSecret := alnum40
	togetherKey := strings.Repeat("0123456789abcdef", 4)
	deepseekKey := "sk-" + hex32
	privateKeyBody := "-----BEGIN " + "PRIVATE KEY-----" + `\n` + strings.Repeat("M", 40) + `\n-----END ` + "PRIVATE KEY-----"
	gcpLine := `{"type": "service_account", "private_key": "` + privateKeyBody + `"}`

	return []fixture{
		{"anthropic", `ANTHROPIC_API_KEY="` + anthropicKey + `"`, anthropicKey, "anthropic", "api-key", finding.ConfidenceHigh},
		{"openai project", "export OPENAI_API_KEY=" + openaiProject, openaiProject, "openai", "project-key", finding.ConfidenceHigh},
		{"openai legacy", "key: " + openaiLegacy, openaiLegacy, "openai", "legacy-key", finding.ConfidenceHigh},
		{"google ai studio", "GEMINI_API_KEY=" + googleKey, googleKey, "google-ai-studio", "api-key", finding.ConfidenceHigh},
		{"fireworks", "token = '" + fireworksKey + "'", fireworksKey, "fireworks", "api-key", finding.ConfidenceHigh},
		{"groq", "GROQ_API_KEY=" + groqKey, groqKey, "groq", "api-key", finding.ConfidenceHigh},
		{"openrouter", "OPENROUTER_API_KEY=" + openrouterKey, openrouterKey, "openrouter", "api-key", finding.ConfidenceHigh},
		{"xai", "XAI_API_KEY=" + xaiKey, xaiKey, "xai", "api-key", finding.ConfidenceHigh},
		{"hugging face", "HF_TOKEN=" + hfKey, hfKey, "huggingface", "access-token", finding.ConfidenceHigh},
		{"replicate", "REPLICATE_API_TOKEN=" + replicateKey, replicateKey, "replicate", "api-token", finding.ConfidenceHigh},
		{"perplexity", "PERPLEXITY_API_KEY=" + perplexityKey, perplexityKey, "perplexity", "api-key", finding.ConfidenceHigh},
		{"aws access key id", "AWS_ACCESS_KEY_ID=" + awsKeyID, awsKeyID, "aws", "access-key-id", finding.ConfidenceHigh},
		{"aws secret access key", "AWS_SECRET_ACCESS_KEY=" + awsSecret, awsSecret, "aws", "secret-access-key", finding.ConfidenceMedium},
		{"together", "TOGETHER_API_KEY=" + togetherKey, togetherKey, "together", "api-key", finding.ConfidenceMedium},
		{"mistral", "MISTRAL_API_KEY=" + alnum32, alnum32, "mistral", "api-key", finding.ConfidenceMedium},
		{"cohere", `"COHERE_API_KEY": "` + alnum40 + `"`, alnum40, "cohere", "api-key", finding.ConfidenceMedium},
		{"deepseek", "DEEPSEEK_API_KEY=" + deepseekKey, deepseekKey, "deepseek", "api-key", finding.ConfidenceMedium},
		{"azure openai", "AZURE_OPENAI_API_KEY=" + alnum32, alnum32, "azure-openai", "api-key", finding.ConfidenceMedium},
		{"gcp service account", gcpLine, `"private_key": "` + privateKeyBody + `"`, "gcp", "service-account-private-key", finding.ConfidenceHigh},
	}
}

func negativeFixtures() []struct{ name, line string } {
	return []struct{ name, line string }{
		{"empty line", ""},
		{"prose", "Set your key in the environment before running."},
		{"env name only", "OPENAI_API_KEY"},
		{"shell reference", "OPENAI_API_KEY=${OPENAI_API_KEY}"},
		{"actions reference", "OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}"},
		{"empty value", "ANTHROPIC_API_KEY="},
		{"short anthropic prefix", "sk-" + "ant-short"},
		{"short openai value", "sk-" + "abc123"},
		{"prefix inside word", "risk-assessment-" + strings.Repeat("a", 48)},
		{"task prefix inside word", "task-" + strings.Repeat("a", 48)},
		{"aws id too short", "AK" + "IA" + strings.Repeat("A", 15)},
		{"low entropy context value", "MISTRAL_API_KEY=" + strings.Repeat("a", 32)},
		{"context value wrong length", "MISTRAL_API_KEY=" + alnum32 + "extra"},
		{"unrelated assignment", "RETRY_COUNT=" + alnum32},
		{"hex digest without context", strings.Repeat("0123456789abcdef", 4)},
		{"private key marker without json", "-----BEGIN " + "PRIVATE KEY-----"},
	}
}

func loadCatalogue(t *testing.T) *Catalogue {
	t.Helper()
	catalogue, err := LoadCatalogue()
	if err != nil {
		t.Fatalf("LoadCatalogue: %v", err)
	}
	return catalogue
}

func TestDetectPositive(t *testing.T) {
	catalogue := loadCatalogue(t)
	for _, tt := range positiveFixtures() {
		t.Run(tt.name, func(t *testing.T) {
			matches := catalogue.Detect(tt.line)
			if len(matches) != 1 {
				t.Fatalf("got %d matches, want 1: %+v", len(matches), matches)
			}
			match := matches[0]
			if match.Provider != tt.provider || match.Format != tt.format {
				t.Errorf("got %s/%s, want %s/%s", match.Provider, match.Format, tt.provider, tt.format)
			}
			if match.Confidence != tt.confidence {
				t.Errorf("confidence = %s, want %s", match.Confidence, tt.confidence)
			}
			if got := tt.line[match.Start:match.End]; got != tt.secret {
				t.Errorf("span %q is not the secret", got)
			}
			if match.Fingerprint != Fingerprint(tt.line[match.Start:match.End]) {
				t.Errorf("fingerprint does not match the matched span")
			}
			if strings.Contains(match.Redacted, tt.line[match.Start:match.End]) {
				t.Errorf("redacted form contains the full secret")
			}
		})
	}
}

func TestDetectNegative(t *testing.T) {
	catalogue := loadCatalogue(t)
	for _, tt := range negativeFixtures() {
		t.Run(tt.name, func(t *testing.T) {
			if matches := catalogue.Detect(tt.line); len(matches) != 0 {
				t.Errorf("got %d matches, want 0: %+v", len(matches), matches)
			}
		})
	}
}

func TestEveryFormatHasPositiveFixture(t *testing.T) {
	catalogue := loadCatalogue(t)
	covered := make(map[string]bool)
	for _, tt := range positiveFixtures() {
		covered[tt.provider+"/"+tt.format] = true
	}
	for _, compiled := range catalogue.compiled {
		key := compiled.provider.ID + "/" + compiled.format.Name
		if !covered[key] {
			t.Errorf("format %s has no positive fixture", key)
		}
	}
}

func TestDetectMultipleAndOverlap(t *testing.T) {
	catalogue := loadCatalogue(t)
	anthropicKey := "sk-" + "ant-" + strings.Repeat("x", 40)
	openaiKey := "sk-" + strings.Repeat("b", 48)

	tests := []struct {
		name      string
		line      string
		wantCount int
	}{
		{"two keys one line", anthropicKey + " " + openaiKey, 2},
		{"same key twice", anthropicKey + "," + anthropicKey, 2},
		{"prefixed key wins over context", "DEEPSEEK_API_KEY=sk-" + strings.Repeat("a", 48), 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := catalogue.Detect(tt.line)
			if len(matches) != tt.wantCount {
				t.Fatalf("got %d matches, want %d: %+v", len(matches), tt.wantCount, matches)
			}
			for i := 1; i < len(matches); i++ {
				if matches[i].Start < matches[i-1].End {
					t.Errorf("matches overlap: %+v", matches)
				}
			}
		})
	}
}

func TestRedactLine(t *testing.T) {
	catalogue := loadCatalogue(t)
	key := "sk-" + "ant-" + strings.Repeat("x", 90)

	tests := []struct {
		name string
		line string
		want string
	}{
		{"no secret", "image: nginx:latest", "image: nginx:latest"},
		{"single secret", "ANTHROPIC_API_KEY=" + key + " # prod", "ANTHROPIC_API_KEY=" + Redact(key) + " # prod"},
		{"secret at line start", key, Redact(key)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := catalogue.RedactLine(tt.line)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
			if strings.Contains(got, key) {
				t.Errorf("redacted line still contains the secret")
			}
		})
	}
}

func TestParseCatalogueErrors(t *testing.T) {
	tests := []struct {
		name string
		yaml string
	}{
		{"invalid yaml", "- id: [unclosed"},
		{"unknown field", "- id: a\n  name: A\n  reach: r\n  bogus: 1\n  formats:\n    - {name: k, pattern: 'a+'}\n"},
		{"missing id", "- name: A\n  reach: r\n  formats:\n    - {name: k, pattern: 'a+'}\n"},
		{"missing reach", "- {id: a, name: A, formats: [{name: k, pattern: 'a+'}]}\n"},
		{"duplicate id", "- {id: a, name: A, reach: r, formats: [{name: k, pattern: 'a+'}]}\n- {id: a, name: B, reach: r, formats: [{name: k, pattern: 'b+'}]}\n"},
		{"no formats", "- id: a\n  name: A\n  reach: r\n"},
		{"bad regex", "- {id: a, name: A, reach: r, formats: [{name: k, pattern: '('}]}\n"},
		{"missing pattern", "- {id: a, name: A, reach: r, formats: [{name: k}]}\n"},
		{"context without env vars", "- {id: a, name: A, reach: r, formats: [{name: k, pattern: 'a+', context: true}]}\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parseCatalogue([]byte(tt.yaml)); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

func TestCatalogueLookups(t *testing.T) {
	catalogue := loadCatalogue(t)

	tests := []struct {
		envVar       string
		wantProvider string
		wantOK       bool
	}{
		{"OPENAI_API_KEY", "openai", true},
		{"ANTHROPIC_API_KEY", "anthropic", true},
		{"AWS_ACCESS_KEY_ID", "aws", true},
		{"PATH", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.envVar, func(t *testing.T) {
			got, ok := catalogue.ProviderForEnvVar(tt.envVar)
			if got != tt.wantProvider || ok != tt.wantOK {
				t.Errorf("got %q, %v, want %q, %v", got, ok, tt.wantProvider, tt.wantOK)
			}
		})
	}

	if names := catalogue.EnvVars(); len(names) == 0 {
		t.Error("EnvVars returned nothing")
	}
	if len(catalogue.Providers()) < 15 {
		t.Errorf("catalogue has %d providers, want at least 15", len(catalogue.Providers()))
	}
}

func TestUnverifiedExcludesVerifiedFormats(t *testing.T) {
	catalogue := loadCatalogue(t)
	for _, entry := range catalogue.Unverified() {
		if entry.Provider == "aws" && entry.Format == "access-key-id" {
			t.Error("aws access-key-id is verified and must not be listed")
		}
	}
	if len(catalogue.Unverified()) == 0 {
		t.Error("expected unverified formats")
	}
}
