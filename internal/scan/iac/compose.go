package iac

import (
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/ryankshah/jackproof/internal/graph"
)

func ParseCompose(path string, data []byte) ([]Workload, error) {
	roots, err := decodeDocuments(data)
	if err != nil {
		return nil, err
	}
	var workloads []Workload
	for _, root := range roots {
		for _, service := range pairs(get(root, "services")) {
			workload := Workload{
				Kind: graph.HolderComposeService,
				Name: service.key.Value,
				Path: path,
				Line: service.key.Line,
			}
			workload.Env = append(workload.Env, composeEnv(get(service.value, "environment"), graph.DeliveryEnv)...)
			workload.Env = append(workload.Env, composeEnv(get(get(service.value, "build"), "args"), graph.DeliveryBuildArg)...)
			workload.EnvFiles = composeEnvFiles(get(service.value, "env_file"))
			workload.Telemetry = telemetryVar(workload.Env)
			if reason, ok := LooksUntrusted(service.key.Value, scalar(get(service.value, "image"))); ok {
				workload.Untrusted = true
				workload.UntrustedReason = reason
			}
			workloads = append(workloads, workload)
		}
	}
	return workloads, nil
}

func composeEnv(node *yaml.Node, delivery graph.Delivery) []EnvVar {
	plain := delivery == graph.DeliveryEnv
	var out []EnvVar
	for _, entry := range pairs(node) {
		variable := EnvVar{Name: entry.key.Value, Delivery: delivery, Plain: plain, Line: entry.key.Line}
		if isNull(entry.value) {
			variable.Kind = ValueEmpty
			variable.Source = entry.key.Value
		} else {
			variable.Value = scalar(entry.value)
			variable.Kind, variable.Source = ClassifyValue(variable.Value)
		}
		out = append(out, variable)
	}
	for _, item := range items(node) {
		text := scalar(item)
		name, value, hasValue := strings.Cut(text, "=")
		variable := EnvVar{Name: name, Delivery: delivery, Plain: plain, Line: item.Line}
		if hasValue {
			variable.Value = value
			variable.Kind, variable.Source = ClassifyValue(value)
		} else {
			variable.Kind = ValueEmpty
			variable.Source = name
		}
		out = append(out, variable)
	}
	return out
}

func composeEnvFiles(node *yaml.Node) []EnvFile {
	node = resolve(node)
	if node == nil {
		return nil
	}
	if node.Kind == yaml.ScalarNode {
		return []EnvFile{{Path: node.Value, Line: node.Line}}
	}
	var out []EnvFile
	for _, item := range items(node) {
		if item.Kind == yaml.ScalarNode {
			out = append(out, EnvFile{Path: item.Value, Line: item.Line})
			continue
		}
		if path := scalar(get(item, "path")); path != "" {
			out = append(out, EnvFile{Path: path, Line: item.Line})
		}
	}
	return out
}
