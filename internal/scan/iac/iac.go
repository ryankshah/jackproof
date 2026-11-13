package iac

import (
	"regexp"

	"github.com/ryankshah/jackproof/internal/graph"
)

type ValueKind int

const (
	ValueEmpty ValueKind = iota
	ValueLiteral
	ValueInterpolated
	ValueSecretRef
)

type EnvVar struct {
	Name     string
	Value    string
	Kind     ValueKind
	Source   string
	Delivery graph.Delivery
	Plain    bool
	Line     int
}

type EnvFile struct {
	Path string
	Line int
}

type Copy struct {
	Source string
	Line   int
}

type EnvDump struct {
	Command string
	Line    int
}

type Workload struct {
	Kind            graph.HolderKind
	Name            string
	Path            string
	Line            int
	Namespace       string
	Environment     string
	Env             []EnvVar
	EnvFiles        []EnvFile
	Copies          []Copy
	Untrusted       bool
	UntrustedReason string
	UntrustedProven bool
	Telemetry       EnvVar
	EnvDumps        []EnvDump
}

var (
	braceInterpolation = regexp.MustCompile(`^\$\{([A-Za-z_][A-Za-z0-9_]*)(?::?[-?+=][^}]*)?\}$`)
	bareInterpolation  = regexp.MustCompile(`^\$([A-Za-z_][A-Za-z0-9_]*)$`)

	untrustedName = regexp.MustCompile(`(?i)(^|[-_./:])(eval|evals|evaluation|evaluator|sandbox|sandboxes|jupyter|notebook|notebooks|runner|plugin|plugins|playground|executor|interpreter)([-_./:]|$)`)

	telemetryVars = map[string]struct{}{
		"SENTRY_DSN":                  {},
		"BUGSNAG_API_KEY":             {},
		"ROLLBAR_ACCESS_TOKEN":        {},
		"DD_API_KEY":                  {},
		"NEW_RELIC_LICENSE_KEY":       {},
		"OTEL_EXPORTER_OTLP_ENDPOINT": {},
		"HONEYCOMB_API_KEY":           {},
	}
)

func ClassifyValue(value string) (ValueKind, string) {
	if value == "" {
		return ValueEmpty, ""
	}
	if match := braceInterpolation.FindStringSubmatch(value); match != nil {
		return ValueInterpolated, match[1]
	}
	if match := bareInterpolation.FindStringSubmatch(value); match != nil {
		return ValueInterpolated, match[1]
	}
	return ValueLiteral, ""
}

func LooksUntrusted(names ...string) (string, bool) {
	for _, name := range names {
		if match := untrustedName.FindStringSubmatch(name); match != nil {
			return "the name " + quote(name), true
		}
	}
	return "", false
}

func quote(value string) string {
	return `"` + value + `"`
}

func telemetryVar(env []EnvVar) EnvVar {
	for _, variable := range env {
		if _, ok := telemetryVars[variable.Name]; ok {
			return variable
		}
	}
	return EnvVar{}
}
