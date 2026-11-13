package iac

import (
	"testing"

	"github.com/ryankshah/jackproof/internal/graph"
)

func envByName(workload Workload, name string) (EnvVar, bool) {
	for _, variable := range workload.Env {
		if variable.Name == name {
			return variable, true
		}
	}
	return EnvVar{}, false
}

func workloadByName(t *testing.T, workloads []Workload, name string) Workload {
	t.Helper()
	for _, workload := range workloads {
		if workload.Name == name {
			return workload
		}
	}
	t.Fatalf("workload %q not found in %d workloads", name, len(workloads))
	return Workload{}
}

func TestClassifyValue(t *testing.T) {
	tests := []struct {
		value      string
		wantKind   ValueKind
		wantSource string
	}{
		{"", ValueEmpty, ""},
		{"plain-text", ValueLiteral, ""},
		{"${OPENAI_API_KEY}", ValueInterpolated, "OPENAI_API_KEY"},
		{"${OPENAI_API_KEY:-fallback}", ValueInterpolated, "OPENAI_API_KEY"},
		{"${OPENAI_API_KEY:?required}", ValueInterpolated, "OPENAI_API_KEY"},
		{"$OPENAI_API_KEY", ValueInterpolated, "OPENAI_API_KEY"},
		{"prefix-${OPENAI_API_KEY}", ValueLiteral, ""},
		{"$(command)", ValueLiteral, ""},
	}
	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			kind, source := ClassifyValue(tt.value)
			if kind != tt.wantKind || source != tt.wantSource {
				t.Errorf("got %v, %q, want %v, %q", kind, source, tt.wantKind, tt.wantSource)
			}
		})
	}
}

func TestLooksUntrusted(t *testing.T) {
	tests := []struct {
		name  string
		names []string
		want  bool
	}{
		{"eval service", []string{"eval-runner"}, true},
		{"sandbox", []string{"code-sandbox"}, true},
		{"jupyter image", []string{"api", "jupyter/base-notebook:latest"}, true},
		{"plugin host", []string{"plugin_host"}, true},
		{"ordinary api", []string{"api", "nginx:1.27"}, false},
		{"word inside another word", []string{"reevaluation", "preplugin", "implugins"}, false},
		{"empty", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reason, got := LooksUntrusted(tt.names...)
			if got != tt.want {
				t.Errorf("got %v (%q), want %v", got, reason, tt.want)
			}
			if got && reason == "" {
				t.Error("untrusted result has no reason")
			}
		})
	}
}

func TestParseDotenv(t *testing.T) {
	data := []byte(`# comment
OPENAI_API_KEY=abc
export ANTHROPIC_API_KEY="quoted value"
SINGLE='single'
SPACED = spaced
TRAILING=value # comment
EMPTY=
invalid line
1BAD=x
`)
	want := map[string]struct {
		value string
		line  int
	}{
		"OPENAI_API_KEY":    {"abc", 2},
		"ANTHROPIC_API_KEY": {"quoted value", 3},
		"SINGLE":            {"single", 4},
		"SPACED":            {"spaced", 5},
		"TRAILING":          {"value", 6},
		"EMPTY":             {"", 7},
	}
	entries := ParseDotenv(data)
	if len(entries) != len(want) {
		t.Fatalf("got %d entries, want %d: %+v", len(entries), len(want), entries)
	}
	for _, entry := range entries {
		expected, ok := want[entry.Name]
		if !ok {
			t.Errorf("unexpected entry %q", entry.Name)
			continue
		}
		if entry.Value != expected.value || entry.Line != expected.line {
			t.Errorf("%s = %q at %d, want %q at %d", entry.Name, entry.Value, entry.Line, expected.value, expected.line)
		}
	}
}

func TestDotenvEntryEnvVar(t *testing.T) {
	tests := []struct {
		name     string
		entry    DotenvEntry
		wantKind ValueKind
	}{
		{"literal", DotenvEntry{Name: "A", Value: "x", Line: 1}, ValueLiteral},
		{"empty", DotenvEntry{Name: "A", Line: 1}, ValueEmpty},
		{"interpolated", DotenvEntry{Name: "A", Value: "${B}", Line: 1}, ValueInterpolated},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			variable := tt.entry.EnvVar(graph.DeliveryEnvFile)
			if variable.Kind != tt.wantKind || variable.Delivery != graph.DeliveryEnvFile || !variable.Plain {
				t.Errorf("got %+v", variable)
			}
		})
	}
}

func TestParseCompose(t *testing.T) {
	data := []byte(`x-common: &common
  environment:
    SHARED_SETTING: "1"
services:
  api:
    image: nginx:1.27
    environment:
      OPENAI_API_KEY: ${OPENAI_API_KEY}
      LITERAL_KEY: not-a-secret
      PASSTHROUGH:
      SENTRY_DSN: https://example.invalid/1
    env_file:
      - .env
      - path: other.env
        required: false
  eval-runner:
    image: runner:latest
    environment:
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
      - PLAIN=value
      - BARE
    env_file: single.env
    build:
      args:
        HF_TOKEN: ${HF_TOKEN}
  merged:
    <<: *common
`)
	workloads, err := ParseCompose("deploy/compose.yaml", data)
	if err != nil {
		t.Fatal(err)
	}
	if len(workloads) != 3 {
		t.Fatalf("got %d workloads, want 3", len(workloads))
	}

	api := workloadByName(t, workloads, "api")
	if api.Kind != graph.HolderComposeService || api.Path != "deploy/compose.yaml" || api.Line != 5 {
		t.Errorf("api header = %+v", api)
	}
	if api.Untrusted {
		t.Error("api should not be untrusted")
	}
	if api.Telemetry.Name != "SENTRY_DSN" {
		t.Errorf("telemetry sink = %q", api.Telemetry.Name)
	}
	if got := len(api.EnvFiles); got != 2 || api.EnvFiles[0].Path != ".env" || api.EnvFiles[1].Path != "other.env" {
		t.Errorf("env files = %+v", api.EnvFiles)
	}
	openai, _ := envByName(api, "OPENAI_API_KEY")
	if openai.Kind != ValueInterpolated || openai.Source != "OPENAI_API_KEY" || openai.Line != 8 || !openai.Plain {
		t.Errorf("OPENAI_API_KEY = %+v", openai)
	}
	passthrough, _ := envByName(api, "PASSTHROUGH")
	if passthrough.Kind != ValueEmpty || passthrough.Source != "PASSTHROUGH" {
		t.Errorf("PASSTHROUGH = %+v", passthrough)
	}
	literal, _ := envByName(api, "LITERAL_KEY")
	if literal.Kind != ValueLiteral || literal.Value != "not-a-secret" {
		t.Errorf("LITERAL_KEY = %+v", literal)
	}

	runner := workloadByName(t, workloads, "eval-runner")
	if !runner.Untrusted || runner.UntrustedReason == "" || runner.UntrustedProven {
		t.Errorf("eval-runner untrusted fields = %v %q %v", runner.Untrusted, runner.UntrustedReason, runner.UntrustedProven)
	}
	if len(runner.EnvFiles) != 1 || runner.EnvFiles[0].Path != "single.env" {
		t.Errorf("runner env files = %+v", runner.EnvFiles)
	}
	anthropic, _ := envByName(runner, "ANTHROPIC_API_KEY")
	if anthropic.Kind != ValueInterpolated || anthropic.Source != "ANTHROPIC_API_KEY" {
		t.Errorf("ANTHROPIC_API_KEY = %+v", anthropic)
	}
	bare, _ := envByName(runner, "BARE")
	if bare.Kind != ValueEmpty {
		t.Errorf("BARE = %+v", bare)
	}
	token, _ := envByName(runner, "HF_TOKEN")
	if token.Delivery != graph.DeliveryBuildArg || token.Plain {
		t.Errorf("HF_TOKEN = %+v", token)
	}
}

func TestParseComposeErrors(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{"invalid yaml", "services: [unclosed"},
		{"mapping value in wrong place", "key: value: extra\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseCompose("compose.yaml", []byte(tt.data)); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

func TestParseComposeNoServices(t *testing.T) {
	workloads, err := ParseCompose("compose.yaml", []byte("version: '3'\n"))
	if err != nil || len(workloads) != 0 {
		t.Errorf("got %v, %v", workloads, err)
	}
}

func TestIsKubernetes(t *testing.T) {
	tests := []struct {
		name string
		data string
		want bool
	}{
		{"manifest", "apiVersion: v1\nkind: Pod\n", true},
		{"json manifest", `{"apiVersion": "v1", "kind": "Pod"}`, true},
		{"compose", "services:\n  web:\n    image: x\n", false},
		{"only kind", "kind: Pod\n", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsKubernetes([]byte(tt.data)); got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseKubernetes(t *testing.T) {
	data := []byte(`apiVersion: v1
kind: ConfigMap
metadata:
  name: ignored
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: chat-api
  namespace: prod
spec:
  template:
    spec:
      containers:
        - name: api
          image: registry.example/chat-api:1
          env:
            - name: OPENAI_API_KEY
              valueFrom:
                secretKeyRef:
                  name: llm-keys
                  key: openai
            - name: LITERAL_VALUE
              value: hello
            - name: EMPTY_VALUE
              value: ""
            - name: FROM_CONFIG
              valueFrom:
                configMapKeyRef:
                  name: settings
                  key: x
          envFrom:
            - secretRef:
                name: bulk-keys
            - configMapRef:
                name: bulk-config
      initContainers:
        - name: init
          image: busybox
          env:
            - name: SENTRY_DSN
              value: https://example.invalid/2
---
apiVersion: batch/v1
kind: CronJob
metadata:
  name: nightly-eval
spec:
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - name: job
              image: eval-harness:2
              env:
                - name: GROQ_API_KEY
                  value: placeholder-value
`)
	workloads, err := ParseKubernetes("k8s/app.yaml", data)
	if err != nil {
		t.Fatal(err)
	}
	if len(workloads) != 2 {
		t.Fatalf("got %d workloads, want 2", len(workloads))
	}

	api := workloadByName(t, workloads, "Deployment/chat-api")
	if api.Namespace != "prod" || api.Untrusted {
		t.Errorf("api = %+v", api)
	}
	key, _ := envByName(api, "OPENAI_API_KEY")
	if key.Kind != ValueSecretRef || key.Source != "k8s-secret:llm-keys/openai" || key.Delivery != graph.DeliverySecretRef || !key.Plain {
		t.Errorf("OPENAI_API_KEY = %+v", key)
	}
	literal, _ := envByName(api, "LITERAL_VALUE")
	if literal.Kind != ValueLiteral || literal.Value != "hello" {
		t.Errorf("LITERAL_VALUE = %+v", literal)
	}
	if _, found := envByName(api, "EMPTY_VALUE"); found {
		t.Error("an empty value should not produce an env var")
	}
	if _, found := envByName(api, "FROM_CONFIG"); found {
		t.Error("configMapKeyRef should not produce an env var")
	}
	bulk := false
	for _, variable := range api.Env {
		if variable.Source == "k8s-secret:bulk-keys/*" && variable.Name == "" {
			bulk = true
		}
	}
	if !bulk {
		t.Errorf("envFrom secretRef missing: %+v", api.Env)
	}
	if api.Telemetry.Name != "SENTRY_DSN" {
		t.Errorf("telemetry sink = %q", api.Telemetry.Name)
	}

	job := workloadByName(t, workloads, "CronJob/nightly-eval")
	if !job.Untrusted {
		t.Error("nightly-eval should be untrusted by name")
	}
	if groq, _ := envByName(job, "GROQ_API_KEY"); groq.Kind != ValueLiteral {
		t.Errorf("GROQ_API_KEY = %+v", groq)
	}
}

func TestParseKubernetesErrors(t *testing.T) {
	if _, err := ParseKubernetes("a.yaml", []byte("kind: [unclosed")); err == nil {
		t.Error("expected an error")
	}
}

func TestParseActions(t *testing.T) {
	data := []byte(`name: ci
on:
  pull_request_target:
    types: [opened]
env:
  WORKFLOW_LEVEL: ${{ secrets.WORKFLOW_SECRET }}
jobs:
  review:
    environment: prod
    runs-on: ubuntu-latest
    env:
      OPENAI_API_KEY: ${{ secrets.OPENAI_PROD_KEY }}
      PLAIN: value
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: some/action@v1
        with:
          api-key: ${{ secrets.ACTION_KEY }}
          other: text
      - name: debug
        run: |
          echo start
          printenv
          curl -H "Authorization: ${{ secrets.INLINE_KEY }}" https://example.invalid
      - run: echo "$ANTHROPIC_API_KEY"
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_KEY }}
  safe:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
`)
	workloads, err := ParseActions(".github/workflows/ci.yml", data)
	if err != nil {
		t.Fatal(err)
	}
	if len(workloads) != 2 {
		t.Fatalf("got %d workloads, want 2", len(workloads))
	}

	review := workloadByName(t, workloads, "review")
	if review.Environment != "prod" {
		t.Errorf("environment = %q", review.Environment)
	}
	if !review.Untrusted || !review.UntrustedProven {
		t.Errorf("untrusted = %v, proven = %v", review.Untrusted, review.UntrustedProven)
	}
	checks := []struct {
		name   string
		source string
		plain  bool
	}{
		{"OPENAI_API_KEY", "gha-secret:OPENAI_PROD_KEY", true},
		{"api-key", "gha-secret:ACTION_KEY", false},
		{"ANTHROPIC_API_KEY", "gha-secret:ANTHROPIC_KEY", true},
		{"WORKFLOW_LEVEL", "gha-secret:WORKFLOW_SECRET", true},
	}
	for _, check := range checks {
		variable, found := envByName(review, check.name)
		if !found || variable.Kind != ValueSecretRef || variable.Source != check.source || variable.Plain != check.plain {
			t.Errorf("%s = %+v (found %v)", check.name, variable, found)
		}
	}
	inline := false
	for _, variable := range review.Env {
		if variable.Name == "" && variable.Source == "gha-secret:INLINE_KEY" && variable.Line == 26 {
			inline = true
		}
	}
	if !inline {
		t.Errorf("inline run secret missing: %+v", review.Env)
	}
	if len(review.EnvDumps) != 1 || review.EnvDumps[0].Line != 25 {
		t.Errorf("env dumps = %+v", review.EnvDumps)
	}
	if plain, _ := envByName(review, "PLAIN"); plain.Kind != ValueLiteral {
		t.Errorf("PLAIN = %+v", plain)
	}

	safe := workloadByName(t, workloads, "safe")
	if !safe.Untrusted || safe.UntrustedProven {
		t.Errorf("safe untrusted = %v, proven = %v", safe.Untrusted, safe.UntrustedProven)
	}
}

func TestParseActionsTriggers(t *testing.T) {
	tests := []struct {
		name          string
		on            string
		wantUntrusted bool
	}{
		{"scalar push", "on: push", false},
		{"list with target", "on: [push, pull_request_target]", true},
		{"mapping pull_request", "on:\n  pull_request:\n    branches: [main]", false},
		{"mapping target", "on:\n  pull_request_target:", true},
		{"scalar target", "on: pull_request_target", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := []byte(tt.on + "\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n")
			workloads, err := ParseActions("wf.yml", data)
			if err != nil || len(workloads) != 1 {
				t.Fatalf("got %v, %v", workloads, err)
			}
			if workloads[0].Untrusted != tt.wantUntrusted {
				t.Errorf("untrusted = %v, want %v", workloads[0].Untrusted, tt.wantUntrusted)
			}
		})
	}
}

func TestEnvDumpCommand(t *testing.T) {
	tests := []struct {
		line string
		want bool
	}{
		{"printenv", true},
		{"env", true},
		{"env | sort", true},
		{"cd x && env > out.txt", true},
		{"set -x", true},
		{"set -ex", true},
		{"export -p", true},
		{"echo ${{ toJSON(secrets) }}", true},
		{"env FOO=bar ./run.sh", false},
		{"echo environment", false},
		{"npm run env-check", false},
		{"echo hello", false},
	}
	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			if got := envDumpCommand.MatchString(tt.line); got != tt.want {
				t.Errorf("match = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseDockerfile(t *testing.T) {
	data := []byte(`FROM python:3.12
# comment
ARG BUILD_TOKEN
ARG HF_TOKEN=default-value
ENV OPENAI_API_KEY=value1 \
    OTHER="two words"
ENV LEGACY form with spaces
ENV FROM_ARG=$BUILD_TOKEN
COPY --chown=app:app .env ./config/
COPY requirements.txt app.py /srv/
ADD ./local.env /srv/
RUN pip install -r requirements.txt
`)
	workload := ParseDockerfile("svc/Dockerfile", data)
	if workload.Kind != graph.HolderDockerfile || workload.Name != "Dockerfile" {
		t.Errorf("header = %+v", workload)
	}
	checks := []struct {
		name     string
		kind     ValueKind
		delivery graph.Delivery
		line     int
		value    string
	}{
		{"BUILD_TOKEN", ValueEmpty, graph.DeliveryBuildArg, 3, ""},
		{"HF_TOKEN", ValueLiteral, graph.DeliveryBuildArg, 4, "default-value"},
		{"OPENAI_API_KEY", ValueLiteral, graph.DeliveryImageEnv, 5, "value1"},
		{"OTHER", ValueLiteral, graph.DeliveryImageEnv, 5, "two words"},
		{"LEGACY", ValueLiteral, graph.DeliveryImageEnv, 7, "form with spaces"},
		{"FROM_ARG", ValueInterpolated, graph.DeliveryImageEnv, 8, "$BUILD_TOKEN"},
	}
	for _, check := range checks {
		variable, found := envByName(workload, check.name)
		if !found {
			t.Errorf("%s not found", check.name)
			continue
		}
		if variable.Kind != check.kind || variable.Delivery != check.delivery || variable.Line != check.line || variable.Value != check.value {
			t.Errorf("%s = %+v, want kind %v delivery %v line %d value %q", check.name, variable, check.kind, check.delivery, check.line, check.value)
		}
	}
	var sources []string
	for _, copied := range workload.Copies {
		sources = append(sources, copied.Source)
	}
	want := []string{".env", "requirements.txt", "app.py", "./local.env"}
	if len(sources) != len(want) {
		t.Fatalf("copy sources = %v, want %v", sources, want)
	}
	for i := range want {
		if sources[i] != want[i] {
			t.Errorf("copy source %d = %q, want %q", i, sources[i], want[i])
		}
	}
	if workload.Copies[0].Line != 9 {
		t.Errorf("first copy line = %d, want 9", workload.Copies[0].Line)
	}
}

func TestParseDevcontainer(t *testing.T) {
	data := []byte(`{
  // comment
  "name": "dev",
  "containerEnv": {
    "OPENAI_API_KEY": "${localEnv:OPENAI_API_KEY}",
    "LITERAL": "value", /* inline */
  },
  "remoteEnv": {
    "ANTHROPIC_API_KEY": "${localEnv:ANTHROPIC_API_KEY:default}"
  },
  "build": {"args": {"HF_TOKEN": "${localEnv:HF_TOKEN}"}},
  "runArgs": ["--env-file", ".env.dev", "--env-file=other.env", "--network=host"],
}
`)
	workload, err := ParseDevcontainer(".devcontainer/devcontainer.json", data)
	if err != nil {
		t.Fatal(err)
	}
	openai, _ := envByName(workload, "OPENAI_API_KEY")
	if openai.Kind != ValueInterpolated || openai.Source != "OPENAI_API_KEY" || openai.Line != 5 {
		t.Errorf("OPENAI_API_KEY = %+v", openai)
	}
	anthropic, _ := envByName(workload, "ANTHROPIC_API_KEY")
	if anthropic.Kind != ValueInterpolated || anthropic.Source != "ANTHROPIC_API_KEY" {
		t.Errorf("ANTHROPIC_API_KEY = %+v", anthropic)
	}
	if literal, _ := envByName(workload, "LITERAL"); literal.Kind != ValueLiteral {
		t.Errorf("LITERAL = %+v", literal)
	}
	if arg, _ := envByName(workload, "HF_TOKEN"); arg.Delivery != graph.DeliveryBuildArg {
		t.Errorf("HF_TOKEN = %+v", arg)
	}
	if len(workload.EnvFiles) != 2 || workload.EnvFiles[0].Path != ".env.dev" || workload.EnvFiles[1].Path != "other.env" {
		t.Errorf("env files = %+v", workload.EnvFiles)
	}
}

func TestParseDevcontainerError(t *testing.T) {
	if _, err := ParseDevcontainer("devcontainer.json", []byte("{ not json")); err == nil {
		t.Error("expected an error")
	}
}
