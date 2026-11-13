package iac

import (
	"fmt"
	"regexp"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/ryankshah/jackproof/internal/graph"
)

const pullRequestTarget = "pull_request_target"

var (
	secretExpression = regexp.MustCompile(`\$\{\{\s*secrets\.([A-Za-z0-9_]+)\s*\}\}`)
	pullRequestRef   = regexp.MustCompile(`github\.event\.pull_request\.head|github\.head_ref|github\.event\.workflow_run\.head`)
	envDumpCommand   = regexp.MustCompile(`(?:^|[;&|(]\s*)(?:printenv|env)\s*(?:$|[|>;&)])|\bprintenv\b|\bset\s+-[a-z]*x|\bexport\s+-p\b|\bdeclare\s+-[a-z]*[xp]\b|toJSON\(\s*(?:secrets|env)\s*\)`)
)

func ParseActions(path string, data []byte) ([]Workload, error) {
	roots, err := decodeDocuments(data)
	if err != nil {
		return nil, err
	}
	var workloads []Workload
	for _, root := range roots {
		triggers := actionTriggers(get(root, "on"))
		workflowEnv := actionEnv(get(root, "env"))
		for _, job := range pairs(get(root, "jobs")) {
			workload := Workload{
				Kind: graph.HolderGitHubJob,
				Name: job.key.Value,
				Path: path,
				Line: job.key.Line,
			}
			workload.Environment = jobEnvironment(get(job.value, "environment"))
			workload.Env = append(workload.Env, workflowEnv...)
			workload.Env = append(workload.Env, actionEnv(get(job.value, "env"))...)
			checksOutPullRequest := false
			for _, step := range items(get(job.value, "steps")) {
				workload.Env = append(workload.Env, actionEnv(get(step, "env"))...)
				workload.Env = append(workload.Env, actionWith(get(step, "with"))...)
				if run := get(step, "run"); run != nil {
					env, dumps := actionRun(run)
					workload.Env = append(workload.Env, env...)
					workload.EnvDumps = append(workload.EnvDumps, dumps...)
				}
				if strings.HasPrefix(scalar(get(step, "uses")), "actions/checkout") && pullRequestRef.MatchString(scalar(get(get(step, "with"), "ref"))) {
					checksOutPullRequest = true
				}
			}
			if triggers[pullRequestTarget] {
				workload.Untrusted = true
				workload.UntrustedReason = "the pull_request_target trigger"
				workload.UntrustedProven = checksOutPullRequest
			}
			workloads = append(workloads, workload)
		}
	}
	return workloads, nil
}

func actionTriggers(node *yaml.Node) map[string]bool {
	triggers := make(map[string]bool)
	node = resolve(node)
	if node == nil {
		return triggers
	}
	switch node.Kind {
	case yaml.ScalarNode:
		triggers[node.Value] = true
	case yaml.SequenceNode:
		for _, item := range items(node) {
			triggers[scalar(item)] = true
		}
	case yaml.MappingNode:
		for _, entry := range pairs(node) {
			triggers[entry.key.Value] = true
		}
	}
	return triggers
}

func jobEnvironment(node *yaml.Node) string {
	node = resolve(node)
	if node == nil {
		return ""
	}
	if node.Kind == yaml.ScalarNode {
		return node.Value
	}
	return scalar(get(node, "name"))
}

func actionEnv(node *yaml.Node) []EnvVar {
	var out []EnvVar
	for _, entry := range pairs(node) {
		value := scalar(entry.value)
		variable := EnvVar{Name: entry.key.Value, Value: value, Delivery: graph.DeliveryEnv, Plain: true, Line: entry.key.Line}
		if match := secretExpression.FindStringSubmatch(value); match != nil {
			variable.Kind = ValueSecretRef
			variable.Source = "gha-secret:" + match[1]
			variable.Delivery = graph.DeliverySecretRef
		} else if value != "" {
			variable.Kind = ValueLiteral
		}
		out = append(out, variable)
	}
	return out
}

func actionWith(node *yaml.Node) []EnvVar {
	var out []EnvVar
	for _, entry := range pairs(node) {
		match := secretExpression.FindStringSubmatch(scalar(entry.value))
		if match == nil {
			continue
		}
		out = append(out, EnvVar{
			Name:     entry.key.Value,
			Kind:     ValueSecretRef,
			Source:   "gha-secret:" + match[1],
			Delivery: graph.DeliverySecretRef,
			Line:     entry.key.Line,
		})
	}
	return out
}

func actionRun(run *yaml.Node) ([]EnvVar, []EnvDump) {
	script := scalar(run)
	first := run.Line
	if run.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0 {
		first++
	}
	var env []EnvVar
	var dumps []EnvDump
	for index, line := range strings.Split(script, "\n") {
		lineNumber := first + index
		for _, match := range secretExpression.FindAllStringSubmatch(line, -1) {
			env = append(env, EnvVar{
				Kind:     ValueSecretRef,
				Source:   fmt.Sprintf("gha-secret:%s", match[1]),
				Delivery: graph.DeliverySecretRef,
				Plain:    true,
				Line:     lineNumber,
			})
		}
		if envDumpCommand.MatchString(line) {
			dumps = append(dumps, EnvDump{Command: strings.TrimSpace(line), Line: lineNumber})
		}
	}
	return env, dumps
}
