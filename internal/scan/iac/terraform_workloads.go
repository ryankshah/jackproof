package iac

import (
	"encoding/json"
	"strings"

	"github.com/ryankshah/jackproof/internal/graph"
	"github.com/ryankshah/jackproof/internal/scan/iac/terraform"
)

const unresolvedPrefix = "<unresolved:"

func TerraformWorkloads(module *terraform.Module) []Workload {
	var workloads []Workload
	workloads = append(workloads, ecsWorkloads(module)...)
	workloads = append(workloads, lambdaWorkloads(module)...)
	workloads = append(workloads, cloudRunWorkloads(module)...)
	return workloads
}

func terraformWorkload(block *terraform.Block) Workload {
	return Workload{Kind: graph.HolderTerraform, Name: block.Address(), Path: block.Path, Line: block.Line}
}

func terraformEnvVar(name, value string, line int) EnvVar {
	variable := EnvVar{Name: name, Value: value, Delivery: graph.DeliveryEnv, Plain: true, Line: line}
	if strings.HasPrefix(value, unresolvedPrefix) {
		variable.Kind = ValueEmpty
		variable.Source = name
		variable.Value = ""
		return variable
	}
	variable.Kind, variable.Source = ClassifyValue(value)
	return variable
}

type ecsContainer struct {
	Name        string `json:"name"`
	Image       string `json:"image"`
	Environment []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"environment"`
	Secrets []struct {
		Name      string `json:"name"`
		ValueFrom string `json:"valueFrom"`
	} `json:"secrets"`
}

func ecsWorkloads(module *terraform.Module) []Workload {
	var workloads []Workload
	for _, block := range module.Resources("aws_ecs_task_definition") {
		attribute, ok := block.Attr("container_definitions")
		if !ok {
			continue
		}
		text, known := module.Text(attribute)
		if !known {
			continue
		}
		var containers []ecsContainer
		if err := json.Unmarshal([]byte(text), &containers); err != nil {
			continue
		}
		workload := terraformWorkload(block)
		names := []string{block.Address()}
		for _, container := range containers {
			names = append(names, container.Name, container.Image)
			for _, entry := range container.Environment {
				workload.Env = append(workload.Env, terraformEnvVar(entry.Name, entry.Value, attribute.Line))
			}
			for _, entry := range container.Secrets {
				workload.Env = append(workload.Env, EnvVar{
					Name: entry.Name, Kind: ValueSecretRef, Source: "aws-secret:" + entry.ValueFrom,
					Delivery: graph.DeliverySecretRef, Plain: true, Line: attribute.Line,
				})
			}
		}
		if reason, untrusted := LooksUntrusted(names...); untrusted {
			workload.Untrusted = true
			workload.UntrustedReason = reason
		}
		workload.Telemetry = telemetryVar(workload.Env)
		workloads = append(workloads, workload)
	}
	return workloads
}

func lambdaWorkloads(module *terraform.Module) []Workload {
	var workloads []Workload
	for _, block := range module.Resources("aws_lambda_function") {
		workload := terraformWorkload(block)
		for _, environment := range block.Children("environment") {
			attribute, ok := environment.Attr("variables")
			if !ok {
				continue
			}
			values := module.StringMap(attribute)
			for _, name := range terraform.SortedKeys(values) {
				workload.Env = append(workload.Env, terraformEnvVar(name, values[name], attribute.Line))
			}
		}
		if reason, untrusted := LooksUntrusted(block.Address()); untrusted {
			workload.Untrusted = true
			workload.UntrustedReason = reason
		}
		workload.Telemetry = telemetryVar(workload.Env)
		workloads = append(workloads, workload)
	}
	return workloads
}

func cloudRunWorkloads(module *terraform.Module) []Workload {
	var workloads []Workload
	for _, resourceType := range []string{"google_cloud_run_service", "google_cloud_run_v2_service", "google_cloud_run_v2_job"} {
		for _, block := range module.Resources(resourceType) {
			workload := terraformWorkload(block)
			names := []string{block.Address()}
			for _, container := range cloudRunContainers(block) {
				if attribute, ok := container.Attr("image"); ok {
					if image, known := module.Text(attribute); known {
						names = append(names, image)
					}
				}
				for _, env := range container.Children("env") {
					if variable, ok := cloudRunEnv(module, env); ok {
						workload.Env = append(workload.Env, variable)
					}
				}
			}
			if reason, untrusted := LooksUntrusted(names...); untrusted {
				workload.Untrusted = true
				workload.UntrustedReason = reason
			}
			workload.Telemetry = telemetryVar(workload.Env)
			workloads = append(workloads, workload)
		}
	}
	return workloads
}

func cloudRunContainers(block *terraform.Block) []*terraform.Block {
	var containers []*terraform.Block
	for _, template := range block.Children("template") {
		containers = append(containers, template.Children("containers")...)
		for _, spec := range template.Children("spec") {
			containers = append(containers, spec.Children("containers")...)
		}
	}
	return containers
}

func cloudRunEnv(module *terraform.Module, env *terraform.Block) (EnvVar, bool) {
	nameAttribute, ok := env.Attr("name")
	if !ok {
		return EnvVar{}, false
	}
	name, known := module.Text(nameAttribute)
	if !known {
		return EnvVar{}, false
	}
	if reference, found := cloudRunSecretReference(env); found {
		return EnvVar{
			Name: name, Kind: ValueSecretRef, Source: "gcp-secret:" + secretReferenceName(module, reference),
			Delivery: graph.DeliverySecretRef, Plain: true, Line: nameAttribute.Line,
		}, true
	}
	if valueAttribute, found := env.Attr("value"); found {
		if value, resolved := module.Text(valueAttribute); resolved {
			return terraformEnvVar(name, value, nameAttribute.Line), true
		}
	}
	return EnvVar{}, false
}

func cloudRunSecretReference(env *terraform.Block) (*terraform.Block, bool) {
	for _, sourceType := range []string{"value_source", "value_from"} {
		for _, source := range env.Children(sourceType) {
			if references := source.Children("secret_key_ref"); len(references) > 0 {
				return references[0], true
			}
		}
	}
	return nil, false
}

func secretReferenceName(module *terraform.Module, reference *terraform.Block) string {
	for _, field := range []string{"secret", "name"} {
		if attribute, found := reference.Attr(field); found {
			if text, resolved := module.Text(attribute); resolved {
				return text
			}
		}
	}
	return ""
}
