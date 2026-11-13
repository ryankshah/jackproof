package posture

import (
	"encoding/json"
	"strings"

	"github.com/ryankshah/jackproof/internal/scan/iac/terraform"
)

type awsIdentity struct {
	address  string
	label    string
	location Location
}

type jsonPolicy struct {
	Statement json.RawMessage `json:"Statement"`
}

type jsonStatement struct {
	Effect      string          `json:"Effect"`
	Action      json.RawMessage `json:"Action"`
	NotAction   json.RawMessage `json:"NotAction"`
	Resource    json.RawMessage `json:"Resource"`
	NotResource json.RawMessage `json:"NotResource"`
}

func rawStrings(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		return []string{single}
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err == nil {
		return many
	}
	return nil
}

func (x *extractor) parsePolicyJSON(text string, location Location) []Statement {
	var policy jsonPolicy
	if err := json.Unmarshal([]byte(text), &policy); err != nil || len(policy.Statement) == 0 {
		return nil
	}
	var raws []jsonStatement
	if err := json.Unmarshal(policy.Statement, &raws); err != nil {
		var single jsonStatement
		if err := json.Unmarshal(policy.Statement, &single); err != nil {
			return nil
		}
		raws = []jsonStatement{single}
	}
	var statements []Statement
	for _, raw := range raws {
		if len(raw.NotAction) > 0 || len(raw.NotResource) > 0 {
			x.skipped++
			continue
		}
		statements = append(statements, Statement{
			Effect:    raw.Effect,
			Actions:   rawStrings(raw.Action),
			Resources: rawStrings(raw.Resource),
			Location:  location,
		})
	}
	return statements
}

func (x *extractor) documentStatements(module *terraform.Module) map[string][]Statement {
	documents := make(map[string][]Statement)
	for _, document := range module.DataSources("aws_iam_policy_document") {
		var statements []Statement
		for _, block := range document.Children("statement") {
			if _, negated := block.Attr("not_actions"); negated {
				x.skipped++
				continue
			}
			if _, negated := block.Attr("not_resources"); negated {
				x.skipped++
				continue
			}
			statement := Statement{Effect: "Allow", Location: blockLocation(block)}
			if attribute, ok := block.Attr("effect"); ok {
				if effect, known := module.Text(attribute); known {
					statement.Effect = effect
				}
			}
			if attribute, ok := block.Attr("actions"); ok {
				statement.Actions = module.Strings(attribute)
			}
			if attribute, ok := block.Attr("resources"); ok {
				statement.Resources = module.Strings(attribute)
			}
			statements = append(statements, statement)
		}
		documents[document.Address()] = statements
	}
	return documents
}

func (x *extractor) policyStatements(module *terraform.Module, block *terraform.Block, attributeName string, documents map[string][]Statement) []Statement {
	attribute, ok := block.Attr(attributeName)
	if !ok {
		return nil
	}
	if reference, isReference := attribute.Reference(); isReference {
		if statements, found := documents[reference]; found {
			return statements
		}
	}
	text, known := module.Text(attribute)
	if !known {
		return nil
	}
	return x.parsePolicyJSON(text, attributeLocation(block, attribute))
}

func isAdminLabel(label string) bool {
	return strings.Contains(strings.ToLower(label), "admin")
}

func (x *extractor) grantStatements(identity awsIdentity, attachment Location, statements []Statement) {
	for _, statement := range statements {
		if !strings.EqualFold(statement.Effect, "Allow") {
			continue
		}
		x.addGrant(Grant{
			Cloud:      CloudAWS,
			Subject:    identity.label,
			Identity:   identity.address,
			Attachment: attachment,
			Source:     statement.Location,
			Actions:    statement.Actions,
			Resources:  statement.Resources,
			Admin:      isAdminLabel(identity.label),
		})
	}
}

func (x *extractor) grantManaged(identity awsIdentity, attachment Location, arn string) {
	policy, ok := x.knowledge.managedPolicy(arn)
	if !ok {
		return
	}
	x.addGrant(Grant{
		Cloud:      CloudAWS,
		Subject:    identity.label,
		Identity:   identity.address,
		Attachment: attachment,
		Source:     attachment,
		Actions:    policy.Actions,
		Resources:  []string{"*"},
		Admin:      policy.Admin || isAdminLabel(identity.label),
	})
}

func (x *extractor) aws(module *terraform.Module) {
	documents := x.documentStatements(module)
	identities := make(map[string]awsIdentity)
	for _, resourceType := range []string{"aws_iam_role", "aws_iam_user", "aws_iam_group"} {
		for _, block := range module.Resources(resourceType) {
			identity := awsIdentity{address: block.Address(), label: block.Address(), location: blockLocation(block)}
			if attribute, ok := block.Attr("name"); ok {
				if name, known := module.Text(attribute); known {
					identity.label = name
				}
			}
			identities[identity.address] = identity
			x.anchor(CloudAWS, identity.location)
		}
	}

	managedARNs := make(map[string]string)
	for _, data := range module.DataSources("aws_iam_policy") {
		if attribute, ok := data.Attr("arn"); ok {
			if arn, known := module.Text(attribute); known {
				managedARNs[data.Address()] = arn
			}
		}
	}

	attached := make(map[string]bool)
	policies := make(map[string]*terraform.Block)
	for _, policy := range module.Resources("aws_iam_policy") {
		policies[policy.Address()] = policy
	}

	for _, resourceType := range []string{"aws_iam_role", "aws_iam_user", "aws_iam_group"} {
		for _, block := range module.Resources(resourceType) {
			identity := identities[block.Address()]
			for _, inline := range block.Children("inline_policy") {
				x.grantStatements(identity, blockLocation(block), x.policyStatements(module, inline, "policy", documents))
			}
			if attribute, ok := block.Attr("managed_policy_arns"); ok {
				for _, arn := range module.Strings(attribute) {
					x.grantManaged(identity, attributeLocation(block, attribute), arn)
				}
			}
		}
	}

	for _, spec := range []struct {
		resourceType string
		field        string
	}{
		{"aws_iam_role_policy", "role"}, {"aws_iam_user_policy", "user"}, {"aws_iam_group_policy", "group"},
	} {
		for _, block := range module.Resources(spec.resourceType) {
			identity, found := resolveIdentity(module, block, spec.field, identities)
			if !found {
				continue
			}
			x.grantStatements(identity, blockLocation(block), x.policyStatements(module, block, "policy", documents))
		}
	}

	for _, spec := range []struct {
		resourceType string
		field        string
	}{
		{"aws_iam_role_policy_attachment", "role"}, {"aws_iam_user_policy_attachment", "user"}, {"aws_iam_group_policy_attachment", "group"},
	} {
		for _, block := range module.Resources(spec.resourceType) {
			identity, found := resolveIdentity(module, block, spec.field, identities)
			if !found {
				continue
			}
			x.attachPolicy(module, block, identity, policies, managedARNs, documents, attached)
		}
	}

	for _, block := range module.Resources("aws_iam_policy_attachment") {
		for _, field := range []string{"roles", "users", "groups"} {
			attribute, ok := block.Attr(field)
			if !ok {
				continue
			}
			for _, reference := range attribute.References() {
				if identity, found := identities[reference]; found {
					x.attachPolicy(module, block, identity, policies, managedARNs, documents, attached)
				}
			}
		}
	}

	for address, policy := range policies {
		if attached[address] {
			continue
		}
		identity := awsIdentity{label: address}
		x.grantStatementsUnattached(module, identity, policy, documents)
	}

	x.awsControls(module, documents)
}

func (x *extractor) grantStatementsUnattached(module *terraform.Module, identity awsIdentity, policy *terraform.Block, documents map[string][]Statement) {
	for _, statement := range x.policyStatements(module, policy, "policy", documents) {
		if !strings.EqualFold(statement.Effect, "Allow") {
			continue
		}
		x.addGrant(Grant{
			Cloud:      CloudAWS,
			Subject:    identity.label,
			Attachment: blockLocation(policy),
			Source:     statement.Location,
			Actions:    statement.Actions,
			Resources:  statement.Resources,
			Unattached: true,
		})
	}
}

func resolveIdentity(module *terraform.Module, block *terraform.Block, field string, identities map[string]awsIdentity) (awsIdentity, bool) {
	attribute, ok := block.Attr(field)
	if !ok {
		return awsIdentity{}, false
	}
	if reference, isReference := attribute.Reference(); isReference {
		identity, found := identities[reference]
		return identity, found
	}
	name, known := module.Text(attribute)
	if !known {
		return awsIdentity{}, false
	}
	for _, identity := range identities {
		if identity.label == name {
			return identity, true
		}
	}
	return awsIdentity{label: name}, true
}

func (x *extractor) attachPolicy(module *terraform.Module, block *terraform.Block, identity awsIdentity, policies map[string]*terraform.Block, managedARNs map[string]string, documents map[string][]Statement, attached map[string]bool) {
	attribute, ok := block.Attr("policy_arn")
	if !ok {
		return
	}
	attachment := attributeLocation(block, attribute)
	if reference, isReference := attribute.Reference(); isReference {
		if policy, found := policies[reference]; found {
			attached[reference] = true
			x.grantStatements(identity, attachment, x.policyStatements(module, policy, "policy", documents))
			return
		}
		if arn, found := managedARNs[reference]; found {
			x.grantManaged(identity, attachment, arn)
		}
		return
	}
	if arn, known := module.Text(attribute); known {
		x.grantManaged(identity, attachment, arn)
	}
}

func (x *extractor) awsControls(module *terraform.Module, documents map[string][]Statement) {
	denyTargets := append(x.knowledge.capabilityActions(capabilityEnable, CloudAWS), x.knowledge.capabilityActions(capabilityInvoke, CloudAWS)...)
	for _, block := range module.Resources("aws_organizations_policy") {
		if attribute, ok := block.Attr("type"); ok {
			if policyType, known := module.Text(attribute); known && policyType != "SERVICE_CONTROL_POLICY" {
				continue
			}
		}
		for _, statement := range x.policyStatements(module, block, "content", documents) {
			if strings.EqualFold(statement.Effect, "Deny") && len(matchedActions(statement.Actions, denyTargets)) > 0 {
				x.infra.Guardrails[CloudAWS] = append(x.infra.Guardrails[CloudAWS], Control{Location: statement.Location, Detail: "service control policy denies Bedrock"})
				break
			}
		}
	}

	for _, block := range module.Resources("aws_budgets_budget") {
		budget := Budget{Location: blockLocation(block)}
		for _, filter := range block.Children("cost_filter") {
			if name, ok := filter.Attr("name"); ok {
				if value, known := module.Text(name); known && strings.EqualFold(value, "Service") {
					if values, hasValues := filter.Attr("values"); hasValues {
						budget.Services = append(budget.Services, module.Strings(values)...)
					}
				}
			}
		}
		if attribute, ok := block.Attr("cost_filters"); ok {
			if service, found := module.StringMap(attribute)["Service"]; found {
				budget.Services = append(budget.Services, service)
			}
		}
		x.infra.Budgets[CloudAWS] = append(x.infra.Budgets[CloudAWS], budget)
	}

	for _, block := range module.Resources("aws_bedrock_model_invocation_logging_configuration") {
		control := Control{Location: blockLocation(block), Detail: "Bedrock model invocation logging configuration"}
		if deliveryDisabled(module, block) {
			x.infra.LoggingOff[CloudAWS] = append(x.infra.LoggingOff[CloudAWS], control)
		} else {
			x.infra.Logging[CloudAWS] = append(x.infra.Logging[CloudAWS], control)
		}
	}

	for _, block := range module.Resources("aws_servicequotas_service_quota") {
		if attribute, ok := block.Attr("service_code"); ok {
			if code, known := module.Text(attribute); known && strings.Contains(strings.ToLower(code), "bedrock") {
				x.infra.Quotas[CloudAWS] = append(x.infra.Quotas[CloudAWS], Control{Location: blockLocation(block), Detail: "Bedrock service quota"})
			}
		}
	}

	for _, resourceType := range module.ResourceTypes() {
		if !strings.HasPrefix(resourceType, "aws_") {
			continue
		}
		for _, block := range module.Resources(resourceType) {
			x.anchor(CloudAWS, blockLocation(block))
			if strings.HasPrefix(resourceType, "aws_bedrock") && resourceType != "aws_bedrock_model_invocation_logging_configuration" {
				x.infra.Usage = append(x.infra.Usage, Usage{Service: "bedrock", Location: blockLocation(block)})
			}
		}
	}
}

func deliveryDisabled(module *terraform.Module, block *terraform.Block) bool {
	deliveryFields := []string{"text_data_delivery_enabled", "image_data_delivery_enabled", "embedding_data_delivery_enabled"}
	for _, config := range block.Children("logging_config") {
		disabled := 0
		for _, field := range deliveryFields {
			if attribute, ok := config.Attr(field); ok {
				if enabled, known := module.Bool(attribute); known && !enabled {
					disabled++
				}
			}
		}
		if disabled == len(deliveryFields) {
			return true
		}
	}
	return false
}
