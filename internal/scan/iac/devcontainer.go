package iac

import (
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/ryankshah/jackproof/internal/graph"
)

var (
	localEnvReference = regexp.MustCompile(`^\$\{(?:localEnv|containerEnv):([A-Za-z_][A-Za-z0-9_]*)(?::[^}]*)?\}$`)
	trailingComma     = regexp.MustCompile(`,(\s*[}\]])`)
	envFileArgument   = regexp.MustCompile(`^--env-file(?:=(.+))?$`)
)

type devcontainerFile struct {
	ContainerEnv map[string]string `json:"containerEnv"`
	RemoteEnv    map[string]string `json:"remoteEnv"`
	Build        struct {
		Args map[string]string `json:"args"`
	} `json:"build"`
	RunArgs []string `json:"runArgs"`
}

func ParseDevcontainer(filePath string, data []byte) (Workload, error) {
	var parsed devcontainerFile
	cleaned := trailingComma.ReplaceAllString(stripJSONComments(string(data)), "$1")
	if err := json.Unmarshal([]byte(cleaned), &parsed); err != nil {
		return Workload{}, fmt.Errorf("decode devcontainer json: %w", err)
	}
	lines := strings.Split(string(data), "\n")
	workload := Workload{
		Kind: graph.HolderDevcontainer,
		Name: path.Base(filePath),
		Path: filePath,
		Line: 1,
	}
	workload.Env = append(workload.Env, devcontainerEnv(parsed.ContainerEnv, graph.DeliveryEnv, lines)...)
	workload.Env = append(workload.Env, devcontainerEnv(parsed.RemoteEnv, graph.DeliveryEnv, lines)...)
	workload.Env = append(workload.Env, devcontainerEnv(parsed.Build.Args, graph.DeliveryBuildArg, lines)...)
	for index, argument := range parsed.RunArgs {
		match := envFileArgument.FindStringSubmatch(argument)
		switch {
		case match == nil:
		case match[1] != "":
			workload.EnvFiles = append(workload.EnvFiles, EnvFile{Path: match[1], Line: findLine(lines, argument)})
		case index+1 < len(parsed.RunArgs):
			workload.EnvFiles = append(workload.EnvFiles, EnvFile{Path: parsed.RunArgs[index+1], Line: findLine(lines, parsed.RunArgs[index+1])})
		}
	}
	workload.Telemetry = telemetryVar(workload.Env)
	return workload, nil
}

func devcontainerEnv(values map[string]string, delivery graph.Delivery, lines []string) []EnvVar {
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	var out []EnvVar
	for _, name := range names {
		value := values[name]
		variable := EnvVar{Name: name, Value: value, Delivery: delivery, Plain: delivery == graph.DeliveryEnv, Line: findLine(lines, `"`+name+`"`)}
		if match := localEnvReference.FindStringSubmatch(value); match != nil {
			variable.Kind = ValueInterpolated
			variable.Source = match[1]
		} else {
			variable.Kind, variable.Source = ClassifyValue(value)
		}
		out = append(out, variable)
	}
	return out
}

func findLine(lines []string, needle string) int {
	for index, line := range lines {
		if strings.Contains(line, needle) {
			return index + 1
		}
	}
	return 1
}

func stripJSONComments(text string) string {
	var out strings.Builder
	inString := false
	for i := 0; i < len(text); i++ {
		c := text[i]
		switch {
		case inString:
			out.WriteByte(c)
			if c == '\\' && i+1 < len(text) {
				i++
				out.WriteByte(text[i])
			} else if c == '"' {
				inString = false
			}
		case c == '"':
			inString = true
			out.WriteByte(c)
		case c == '/' && i+1 < len(text) && text[i+1] == '/':
			for i < len(text) && text[i] != '\n' {
				i++
			}
			out.WriteByte('\n')
		case c == '/' && i+1 < len(text) && text[i+1] == '*':
			i += 2
			for i+1 < len(text) && (text[i] != '*' || text[i+1] != '/') {
				if text[i] == '\n' {
					out.WriteByte('\n')
				}
				i++
			}
			i++
		default:
			out.WriteByte(c)
		}
	}
	return out.String()
}
