package posture

import (
	"bytes"
	_ "embed"
	"fmt"
	"regexp"
	"strings"

	"go.yaml.in/yaml/v3"
)

//go:embed knowledge.yaml
var embeddedKnowledge []byte

type Cloud string

const (
	CloudAWS   Cloud = "aws"
	CloudGCP   Cloud = "gcp"
	CloudAzure Cloud = "azure"
)

const (
	capabilityEnable  = "enable-model-access"
	capabilityInvoke  = "invoke-model"
	capabilityLogging = "disable-invocation-logging"
	capabilityKeys    = "create-credential"
)

type capability struct {
	Name     string   `yaml:"name"`
	Cloud    Cloud    `yaml:"cloud"`
	Service  string   `yaml:"service"`
	Actions  []string `yaml:"actions"`
	Verified bool     `yaml:"verified"`
}

type managedPolicy struct {
	ARN      string   `yaml:"arn"`
	Actions  []string `yaml:"actions"`
	Admin    bool     `yaml:"admin"`
	Verified bool     `yaml:"verified"`
}

type gcpRole struct {
	Name        string   `yaml:"name"`
	Permissions []string `yaml:"permissions"`
	Broad       bool     `yaml:"broad"`
	Verified    bool     `yaml:"verified"`
}

type azureRole struct {
	Name     string   `yaml:"name"`
	Actions  []string `yaml:"actions"`
	Broad    bool     `yaml:"broad"`
	Verified bool     `yaml:"verified"`
}

type Service struct {
	ID          string   `yaml:"id"`
	Cloud       Cloud    `yaml:"cloud"`
	Name        string   `yaml:"name"`
	BudgetTerms []string `yaml:"budget_terms"`
}

type Knowledge struct {
	Capabilities    []capability    `yaml:"capabilities"`
	ManagedPolicies []managedPolicy `yaml:"managed_policies"`
	GCPRoles        []gcpRole       `yaml:"gcp_roles"`
	AzureRoles      []azureRole     `yaml:"azure_roles"`
	Services        []Service       `yaml:"services"`
}

func LoadKnowledge() (*Knowledge, error) {
	return parseKnowledge(embeddedKnowledge)
}

func parseKnowledge(data []byte) (*Knowledge, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var knowledge Knowledge
	if err := decoder.Decode(&knowledge); err != nil {
		return nil, fmt.Errorf("parse posture knowledge: %w", err)
	}
	for i, entry := range knowledge.Capabilities {
		if entry.Name == "" || entry.Cloud == "" || entry.Service == "" || len(entry.Actions) == 0 {
			return nil, fmt.Errorf("capability %d needs a name, cloud, service and actions", i)
		}
	}
	for i, service := range knowledge.Services {
		if service.ID == "" || service.Cloud == "" || len(service.BudgetTerms) == 0 {
			return nil, fmt.Errorf("service %d needs an id, cloud and budget terms", i)
		}
	}
	return &knowledge, nil
}

func (k *Knowledge) capabilityActions(name string, cloud Cloud) []string {
	var actions []string
	for _, entry := range k.Capabilities {
		if entry.Name == name && entry.Cloud == cloud {
			actions = append(actions, entry.Actions...)
		}
	}
	return actions
}

func (k *Knowledge) servicesFor(name string, cloud Cloud) []string {
	var services []string
	for _, entry := range k.Capabilities {
		if entry.Name == name && entry.Cloud == cloud {
			services = append(services, entry.Service)
		}
	}
	return services
}

func (k *Knowledge) serviceName(id string) string {
	for _, service := range k.Services {
		if service.ID == id {
			return service.Name
		}
	}
	return id
}

func (k *Knowledge) managedPolicy(arn string) (managedPolicy, bool) {
	for _, policy := range k.ManagedPolicies {
		if policy.ARN == arn {
			return policy, true
		}
	}
	return managedPolicy{}, false
}

func (k *Knowledge) gcpRole(name string) (gcpRole, bool) {
	for _, role := range k.GCPRoles {
		if role.Name == name {
			return role, true
		}
	}
	return gcpRole{}, false
}

func (k *Knowledge) azureRole(name string) (azureRole, bool) {
	for _, role := range k.AzureRoles {
		if strings.EqualFold(role.Name, name) {
			return role, true
		}
	}
	return azureRole{}, false
}

func (k *Knowledge) UnverifiedEntries() []string {
	var entries []string
	for _, entry := range k.Capabilities {
		if !entry.Verified {
			entries = append(entries, fmt.Sprintf("capability:%s/%s/%s", entry.Cloud, entry.Service, entry.Name))
		}
	}
	for _, policy := range k.ManagedPolicies {
		if !policy.Verified {
			entries = append(entries, "managed-policy:"+policy.ARN)
		}
	}
	for _, role := range k.GCPRoles {
		if !role.Verified {
			entries = append(entries, "gcp-role:"+role.Name)
		}
	}
	for _, role := range k.AzureRoles {
		if !role.Verified {
			entries = append(entries, "azure-role:"+role.Name)
		}
	}
	return entries
}

var globCache = make(map[string]*regexp.Regexp)

func globMatches(pattern, value string) bool {
	expression, ok := globCache[pattern]
	if !ok {
		var builder strings.Builder
		builder.WriteString("(?i)^")
		for _, r := range pattern {
			switch r {
			case '*':
				builder.WriteString(".*")
			case '?':
				builder.WriteString(".")
			default:
				builder.WriteString(regexp.QuoteMeta(string(r)))
			}
		}
		builder.WriteString("$")
		expression = regexp.MustCompile(builder.String())
		globCache[pattern] = expression
	}
	return expression.MatchString(value)
}

func matchedActions(granted, targets []string) []string {
	var matched []string
	for _, target := range targets {
		for _, pattern := range granted {
			if globMatches(pattern, target) {
				matched = append(matched, target)
				break
			}
		}
	}
	return matched
}
