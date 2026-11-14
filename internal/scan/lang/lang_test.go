package lang

import (
	"reflect"
	"strings"
	"testing"
)

func credentialEnv(name string) bool {
	switch name {
	case "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "AWS_SECRET_ACCESS_KEY":
		return true
	}
	return false
}

func newTestExtractor(t *testing.T) *Extractor {
	t.Helper()
	extractor, err := New(credentialEnv)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return extractor
}

func TestLanguageFor(t *testing.T) {
	tests := []struct {
		path string
		want string
		ok   bool
	}{
		{"main.go", Go, true},
		{"app/service.py", Python, true},
		{"web/index.js", JavaScript, true},
		{"web/App.tsx", JavaScript, true},
		{"server.mjs", JavaScript, true},
		{"README.md", "", false},
		{"Makefile", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got, ok := LanguageFor(tt.path)
			if got != tt.want || ok != tt.ok {
				t.Errorf("got %q, %v, want %q, %v", got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestGoFacts(t *testing.T) {
	source := `package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	anthropic "github.com/anthropics/anthropic-sdk-go"
	"github.com/sashabaranov/go-openai"
)

type Config struct{ APIKey string }

func main() {
	key := os.Getenv("OPENAI_API_KEY")
	home := os.Getenv("HOME")
	client := openai.NewClient(key)
	other := anthropic.NewClient()
	cfg := Config{APIKey: os.Getenv("ANTHROPIC_API_KEY")}
	log.Printf("using %s", key)
	log.Println("home is", home)
	fmt.Println("prefix: " + key)
	err := fmt.Errorf("auth failed for %s", cfg.APIKey)
	_ = fmt.Sprintf("%d", len(key))
	http.Error(nil, fmt.Sprintf("bad key %s", key), 500)
	log.Println(len(key))
	logger.Infof("key=%s", key)
	_, _, _ = client, other, err
}
`
	facts, err := newTestExtractor(t).Extract(Go, []byte(source))
	if err != nil {
		t.Fatal(err)
	}

	wantReads := map[string]int{"OPENAI_API_KEY": 16, "ANTHROPIC_API_KEY": 20}
	if len(facts.EnvReads) != len(wantReads) {
		t.Errorf("env reads = %+v", facts.EnvReads)
	}
	for _, read := range facts.EnvReads {
		if wantReads[read.Name] != read.Line {
			t.Errorf("env read %+v, want line %d", read, wantReads[read.Name])
		}
	}

	wantClients := map[string]string{"openai": "openai.NewClient", "anthropic": "anthropic.NewClient"}
	if len(facts.Clients) != len(wantClients) {
		t.Errorf("clients = %+v", facts.Clients)
	}
	for _, client := range facts.Clients {
		if wantClients[client.Provider] != client.Constructor {
			t.Errorf("client = %+v", client)
		}
	}

	type leakKey struct {
		line   int
		strong bool
	}
	wantLeaks := map[leakKey]string{
		{21, true}:  "OPENAI_API_KEY",
		{23, true}:  "OPENAI_API_KEY",
		{24, true}:  "ANTHROPIC_API_KEY",
		{26, true}:  "OPENAI_API_KEY",
		{28, false}: "OPENAI_API_KEY",
	}
	got := make(map[leakKey]string)
	for _, leak := range facts.Leaks {
		got[leakKey{leak.Line, leak.Strong}] = leak.Env
	}
	for key, env := range wantLeaks {
		if got[key] != env {
			t.Errorf("missing leak at %+v for %s; got %+v", key, env, facts.Leaks)
		}
	}
	if len(got) != len(wantLeaks) {
		t.Errorf("leaks = %+v, want exactly %d", facts.Leaks, len(wantLeaks))
	}
}

func TestGoNegative(t *testing.T) {
	tests := []struct {
		name   string
		source string
	}{
		{"no credentials", "package main\nimport \"log\"\nfunc main() { log.Println(\"hi\") }\n"},
		{"non credential env", "package main\nimport (\"log\"; \"os\")\nfunc main() { h := os.Getenv(\"HOME\"); log.Println(h) }\n"},
		{"dynamic env name", "package main\nimport (\"log\"; \"os\")\nfunc main() { n := \"OPENAI_API_KEY\"; k := os.Getenv(n); _ = k; log.Println(n) }\n"},
		{"unknown package constructor", "package main\nimport \"example.com/other\"\nfunc main() { other.NewClient() }\n"},
		{"non constructor call", "package main\nimport \"github.com/sashabaranov/go-openai\"\nfunc main() { openai.DefaultConfig(\"x\") }\n"},
	}
	extractor := newTestExtractor(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			facts, err := extractor.Extract(Go, []byte(tt.source))
			if err != nil {
				t.Fatal(err)
			}
			if len(facts.Leaks) != 0 || len(facts.Clients) != 0 {
				t.Errorf("unexpected facts: %+v", facts)
			}
		})
	}
}

func TestGoParseError(t *testing.T) {
	if _, err := newTestExtractor(t).Extract(Go, []byte("package")); err == nil {
		t.Error("expected a parse error")
	}
}

func TestPythonFacts(t *testing.T) {
	source := `import os
import logging
import anthropic
from openai import OpenAI
import boto3

# key = os.environ["OPENAI_API_KEY"]
api_key = os.environ["OPENAI_API_KEY"]
other = os.getenv("HOME")
client = OpenAI(api_key=api_key)
claude = anthropic.Anthropic()
bedrock = boto3.client("bedrock-runtime", region_name="us-east-1")
logging.info(f"key is {api_key}")
print("home", other)
print(os.environ.get("ANTHROPIC_API_KEY"))
raise RuntimeError("failed with " + api_key)
print(api_key_length)
`
	facts, err := newTestExtractor(t).Extract(Python, []byte(source))
	if err != nil {
		t.Fatal(err)
	}
	reads := map[int]string{8: "OPENAI_API_KEY", 15: "ANTHROPIC_API_KEY"}
	if len(facts.EnvReads) != len(reads) {
		t.Errorf("env reads = %+v", facts.EnvReads)
	}
	for _, read := range facts.EnvReads {
		if reads[read.Line] != read.Name {
			t.Errorf("env read = %+v", read)
		}
	}
	clients := map[int]string{10: "openai", 11: "anthropic", 12: "aws"}
	if len(facts.Clients) != len(clients) {
		t.Errorf("clients = %+v", facts.Clients)
	}
	for _, client := range facts.Clients {
		if clients[client.Line] != client.Provider {
			t.Errorf("client = %+v", client)
		}
	}
	leaks := map[int]string{13: "OPENAI_API_KEY", 15: "ANTHROPIC_API_KEY", 16: "OPENAI_API_KEY"}
	if len(facts.Leaks) != len(leaks) {
		t.Errorf("leaks = %+v", facts.Leaks)
	}
	for _, leak := range facts.Leaks {
		if leaks[leak.Line] != leak.Env || leak.Strong {
			t.Errorf("leak = %+v", leak)
		}
	}
}

func TestJavaScriptFacts(t *testing.T) {
	source := `import OpenAI from "openai";
import Anthropic from "@anthropic-ai/sdk";
// const unused = process.env.OPENAI_API_KEY;
const apiKey = process.env.OPENAI_API_KEY;
const home = process.env.HOME;
const openai = new OpenAI({ apiKey });
const claude = new Anthropic({ apiKey: process.env["ANTHROPIC_API_KEY"] });
console.log("key", apiKey);
console.log("home", home);
logger.error(` + "`failed ${apiKey}`" + `);
throw new Error("bad " + apiKey);
res.status(500).send(apiKey);
res.json({ error: process.env.OPENAI_API_KEY });
`
	facts, err := newTestExtractor(t).Extract(JavaScript, []byte(source))
	if err != nil {
		t.Fatal(err)
	}
	clients := map[int]string{6: "openai", 7: "anthropic"}
	if len(facts.Clients) != len(clients) {
		t.Errorf("clients = %+v", facts.Clients)
	}
	for _, client := range facts.Clients {
		if clients[client.Line] != client.Provider {
			t.Errorf("client = %+v", client)
		}
	}
	leaks := map[int]string{8: "OPENAI_API_KEY", 10: "OPENAI_API_KEY", 11: "OPENAI_API_KEY", 13: "OPENAI_API_KEY"}
	got := make(map[int]string)
	for _, leak := range facts.Leaks {
		got[leak.Line] = leak.Env
	}
	for line, env := range leaks {
		if got[line] != env {
			t.Errorf("missing leak at line %d; got %+v", line, facts.Leaks)
		}
	}
	if _, found := got[9]; found {
		t.Error("logging a non-credential value must not be a leak")
	}
	if _, found := got[3]; found {
		t.Error("commented line must be ignored")
	}
}

func TestUnsupportedLanguage(t *testing.T) {
	if _, err := newTestExtractor(t).Extract("ruby", nil); err == nil {
		t.Error("expected an error")
	}
}

func TestEveryClientRuleMatchesSomething(t *testing.T) {
	extractor := newTestExtractor(t)
	samples := map[string][]string{
		Python:     {"anthropic.Anthropic()", "AsyncAnthropic()", "openai.OpenAI()", "AzureOpenAI()", `boto3.client("bedrock-runtime")`, "vertexai.init()", "genai.Client()", "cohere.ClientV2()", "Mistral()", "Groq()", "Together()", "InferenceClient()"},
		JavaScript: {"new OpenAI()", "new Anthropic()", "new GoogleGenerativeAI()", "new BedrockRuntimeClient()", "new CohereClient()", "new Groq()", "new Mistral()", "new HfInference()"},
	}
	for language, rules := range extractor.clients {
		for _, rule := range rules {
			if rule.compiled == nil {
				continue
			}
			matched := false
			for _, sample := range samples[language] {
				if rule.compiled.MatchString(sample) {
					matched = true
				}
			}
			if !matched {
				t.Errorf("%s rule %s matched none of the samples", language, rule.Provider)
			}
		}
	}
}

func TestNewExtractorErrors(t *testing.T) {
	tests := []struct {
		name string
		yaml string
	}{
		{"invalid yaml", "go: ["},
		{"unknown field", "go:\n  - {provider: a, import: x, bogus: 1}\n"},
		{"no provider", "go:\n  - {import: x}\n"},
		{"both import and pattern", "go:\n  - {provider: a, import: x, pattern: y}\n"},
		{"neither", "go:\n  - {provider: a}\n"},
		{"bad regex", "python:\n  - {provider: a, pattern: '('}\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := newExtractor([]byte(tt.yaml), credentialEnv); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

func TestUnverifiedClients(t *testing.T) {
	list := newTestExtractor(t).UnverifiedClients()
	if len(list) == 0 {
		t.Fatal("expected unverified entries")
	}
	for i := 1; i < len(list); i++ {
		if list[i] == list[i-1] {
			t.Errorf("duplicate entry %q", list[i])
		}
	}
	if !strings.Contains(strings.Join(list, ","), "python/anthropic") {
		t.Errorf("list = %v", list)
	}
}

func TestSecretLookups(t *testing.T) {
	extractor := newTestExtractor(t)
	tests := []struct {
		name     string
		language string
		source   string
		want     []SecretLookup
	}{
		{"python aws", Python, "client.get_secret_value(SecretId=\"prod/openai-key\")\n", []SecretLookup{{"aws-secret", "prod/openai-key", 1}}},
		{"python gcp", Python, "name = f\"projects/p/secrets/anthropic-key/versions/latest\"\nclient.access_secret_version(name=name)\n", []SecretLookup{{"gcp-secret", "anthropic-key", 1}}},
		{"python azure", Python, "secret = client.get_secret(\"openai-key\")\n", []SecretLookup{{"azure-secret", "openai-key", 1}}},
		{"python vault", Python, "hvac.read_secret_version(path='kv/openai')\n", []SecretLookup{{"vault-secret", "kv/openai", 1}}},
		{"javascript aws", JavaScript, "new GetSecretValueCommand({ SecretId: 'prod/groq' })\n", []SecretLookup{{"aws-secret", "prod/groq", 1}}},
		{"javascript azure", JavaScript, "await client.getSecret(\"openai-key\");\n", []SecretLookup{{"azure-secret", "openai-key", 1}}},
		{"go aws", Go, "package main\nvar _ = Input{SecretId: aws.String(\"prod/mistral\")}\n", []SecretLookup{{"aws-secret", "prod/mistral", 2}}},
		{"go azure", Go, "package main\nfunc f() { c.GetSecret(ctx, \"openai-key\", \"\", nil) }\n", []SecretLookup{{"azure-secret", "openai-key", 2}}},
		{"commented out", Python, "# client.get_secret_value(SecretId=\"old\")\n", nil},
		{"no lookup", Python, "x = get_secret_value\nprint('secrets')\n", nil},
		{"two on a line", JavaScript, "a(getSecret('one'), getSecret('two'))\n", []SecretLookup{{"azure-secret", "one", 1}, {"azure-secret", "two", 1}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			facts, err := extractor.Extract(tt.language, []byte(tt.source))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(facts.SecretLookups, tt.want) {
				t.Errorf("lookups = %+v, want %+v", facts.SecretLookups, tt.want)
			}
		})
	}
}

func TestLookupPatternsAreValidated(t *testing.T) {
	tests := []struct {
		name string
		yaml string
	}{
		{"no store", "- {pattern: 'a(b)'}\n"},
		{"bad regex", "- {store: s, pattern: '('}\n"},
		{"no capture group", "- {store: s, pattern: 'abc'}\n"},
		{"two capture groups", "- {store: s, pattern: '(a)(b)'}\n"},
		{"unknown field", "- {store: s, pattern: '(a)', bogus: 1}\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parseLookups([]byte(tt.yaml)); err == nil {
				t.Error("expected an error")
			}
		})
	}
	if got := newTestExtractor(t).UnverifiedLookups(); len(got) != 4 {
		t.Errorf("unverified lookups = %v", got)
	}
}

func TestImportMatches(t *testing.T) {
	tests := []struct {
		name       string
		importPath string
		base       string
		want       bool
	}{
		{"exact", "github.com/openai/openai-go", "github.com/openai/openai-go", true},
		{"major version suffix", "github.com/openai/openai-go/v3", "github.com/openai/openai-go", true},
		{"two digit major version", "github.com/openai/openai-go/v12", "github.com/openai/openai-go", true},
		{"sub package", "github.com/openai/openai-go/option", "github.com/openai/openai-go", false},
		{"version suffix with letters", "github.com/openai/openai-go/v3x", "github.com/openai/openai-go", false},
		{"empty version", "github.com/openai/openai-go/v", "github.com/openai/openai-go", false},
		{"different module", "github.com/openai/openai-python", "github.com/openai/openai-go", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := importMatches(tt.importPath, tt.base); got != tt.want {
				t.Errorf("importMatches(%q, %q) = %v, want %v", tt.importPath, tt.base, got, tt.want)
			}
		})
	}
}
