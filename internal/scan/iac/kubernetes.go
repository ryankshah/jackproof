package iac

import (
	"fmt"
	"regexp"

	"go.yaml.in/yaml/v3"

	"github.com/ryankshah/jackproof/internal/graph"
)

var kubernetesMarkers = regexp.MustCompile(`(?m)(?:^|[{,\s])"?(?:apiVersion|kind)"?\s*:`)

func IsKubernetes(data []byte) bool {
	return len(kubernetesMarkers.FindAll(data, 2)) >= 2
}

var podSpecPaths = map[string][]string{
	"Pod":         {"spec"},
	"Deployment":  {"spec", "template", "spec"},
	"StatefulSet": {"spec", "template", "spec"},
	"DaemonSet":   {"spec", "template", "spec"},
	"ReplicaSet":  {"spec", "template", "spec"},
	"Job":         {"spec", "template", "spec"},
	"CronJob":     {"spec", "jobTemplate", "spec", "template", "spec"},
}

func ParseKubernetes(path string, data []byte) ([]Workload, error) {
	roots, err := decodeDocuments(data)
	if err != nil {
		return nil, err
	}
	var workloads []Workload
	for _, root := range roots {
		kind := scalar(get(root, "kind"))
		specPath, workloadKind := podSpecPaths[kind]
		if !workloadKind {
			continue
		}
		spec := root
		for _, key := range specPath {
			spec = get(spec, key)
		}
		metadata := get(root, "metadata")
		name := scalar(get(metadata, "name"))
		workload := Workload{
			Kind:      graph.HolderKubernetes,
			Name:      fmt.Sprintf("%s/%s", kind, name),
			Path:      path,
			Line:      root.Line,
			Namespace: scalar(get(metadata, "namespace")),
		}
		names := []string{name}
		for _, field := range []string{"containers", "initContainers"} {
			for _, container := range items(get(spec, field)) {
				workload.Env = append(workload.Env, containerEnv(container)...)
				names = append(names, scalar(get(container, "name")), scalar(get(container, "image")))
			}
		}
		if reason, ok := LooksUntrusted(names...); ok {
			workload.Untrusted = true
			workload.UntrustedReason = reason
		}
		workload.Telemetry = telemetryVar(workload.Env)
		workloads = append(workloads, workload)
	}
	return workloads, nil
}

func containerEnv(container *yaml.Node) []EnvVar {
	var out []EnvVar
	for _, item := range items(get(container, "env")) {
		variable := EnvVar{Name: scalar(get(item, "name")), Delivery: graph.DeliveryEnv, Plain: true, Line: item.Line}
		secretKey := get(get(item, "valueFrom"), "secretKeyRef")
		switch {
		case secretKey != nil:
			variable.Kind = ValueSecretRef
			variable.Source = fmt.Sprintf("k8s-secret:%s/%s", scalar(get(secretKey, "name")), scalar(get(secretKey, "key")))
			variable.Delivery = graph.DeliverySecretRef
		case scalar(get(item, "value")) != "":
			variable.Value = scalar(get(item, "value"))
			variable.Kind = ValueLiteral
		default:
			continue
		}
		out = append(out, variable)
	}
	for _, source := range items(get(container, "envFrom")) {
		secret := get(source, "secretRef")
		if secret == nil {
			continue
		}
		out = append(out, EnvVar{
			Kind:     ValueSecretRef,
			Source:   fmt.Sprintf("k8s-secret:%s/*", scalar(get(secret, "name"))),
			Delivery: graph.DeliverySecretRef,
			Plain:    true,
			Line:     source.Line,
		})
	}
	return out
}
