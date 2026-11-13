package posture

import (
	"strings"

	"github.com/ryankshah/jackproof/internal/scan/iac/terraform"
)

type azureCustomRole struct {
	name    string
	actions []string
}

func (x *extractor) azure(module *terraform.Module) {
	customRoles := azureCustomRoles(module)
	for _, block := range module.Resources("azurerm_role_assignment") {
		x.azureAssignment(module, block, customRoles)
	}
	x.azureAccounts(module)
	x.azureControls(module)
}

func azureCustomRoles(module *terraform.Module) map[string]azureCustomRole {
	roles := make(map[string]azureCustomRole)
	for _, block := range module.Resources("azurerm_role_definition") {
		role := azureCustomRole{name: block.Address()}
		if attribute, ok := block.Attr("name"); ok {
			if name, known := module.Text(attribute); known {
				role.name = name
			}
		}
		for _, permissions := range block.Children("permissions") {
			for _, field := range []string{"actions", "data_actions"} {
				if attribute, ok := permissions.Attr(field); ok {
					role.actions = append(role.actions, module.Strings(attribute)...)
				}
			}
		}
		roles[block.Address()] = role
	}
	return roles
}

func (x *extractor) azureAssignment(module *terraform.Module, block *terraform.Block, customRoles map[string]azureCustomRole) {
	x.anchor(CloudAzure, blockLocation(block))
	var roleName string
	var actions []string
	var broad bool
	if attribute, ok := block.Attr("role_definition_name"); ok {
		if name, known := module.Text(attribute); known {
			roleName = name
			if role, found := x.knowledge.azureRole(name); found {
				actions, broad = role.Actions, role.Broad
			}
		}
	}
	if attribute, ok := block.Attr("role_definition_id"); ok {
		if reference, isReference := attribute.Reference(); isReference {
			if custom, found := customRoles[reference]; found {
				roleName, actions = custom.name, custom.actions
			}
		}
	}
	if len(actions) == 0 {
		return
	}
	scope := "*"
	if attribute, ok := block.Attr("scope"); ok {
		if text, known := module.Text(attribute); known {
			scope = text
		}
	}
	subject := "unknown principal"
	identity := ""
	if attribute, ok := block.Attr("principal_id"); ok {
		subject = block.Address()
		if reference, isReference := attribute.Reference(); isReference {
			subject, identity = reference, reference
		} else if text, known := module.Text(attribute); known {
			subject = text
		}
	}
	x.addGrant(Grant{
		Cloud:      CloudAzure,
		Subject:    subject,
		Identity:   identity,
		Attachment: blockLocation(block),
		Source:     blockLocation(block),
		Actions:    actions,
		Resources:  []string{scope},
		Admin:      isAdminLabel(subject),
		Role:       roleName,
		Broad:      broad,
	})
}

func (x *extractor) azureAccounts(module *terraform.Module) {
	accounts := make(map[string]int)
	for _, block := range module.Resources("azurerm_cognitive_account") {
		x.anchor(CloudAzure, blockLocation(block))
		kind := ""
		if attribute, ok := block.Attr("kind"); ok {
			kind, _ = module.Text(attribute)
		}
		if !strings.EqualFold(kind, "OpenAI") {
			continue
		}
		accounts[block.Address()] = len(x.infra.Accounts)
		location := blockLocation(block)
		x.infra.Accounts = append(x.infra.Accounts, Account{Address: block.Address(), Location: location, Environment: x.environmentFor(location)})
		x.infra.Usage = append(x.infra.Usage, Usage{Service: "azure-openai", Location: location})
	}
	for _, block := range module.Resources("azurerm_cognitive_deployment") {
		attribute, ok := block.Attr("cognitive_account_id")
		if !ok {
			continue
		}
		reference, isReference := attribute.Reference()
		index, known := accounts[reference]
		if !isReference || !known {
			continue
		}
		limited := false
		for _, sku := range block.Children("sku") {
			if _, hasCapacity := sku.Attr("capacity"); hasCapacity {
				limited = true
			}
		}
		for range block.Children("scale") {
			limited = true
		}
		if limited {
			x.infra.Accounts[index].Limited = true
			x.infra.Quotas[CloudAzure] = append(x.infra.Quotas[CloudAzure], Control{Location: blockLocation(block), Detail: "deployment capacity"})
		} else {
			x.infra.Accounts[index].Deployments = append(x.infra.Accounts[index].Deployments, blockLocation(block))
		}
	}
	for _, block := range module.Resources("azurerm_monitor_diagnostic_setting") {
		attribute, ok := block.Attr("target_resource_id")
		if !ok {
			continue
		}
		if reference, isReference := attribute.Reference(); isReference {
			if index, found := accounts[reference]; found {
				x.infra.Accounts[index].Monitored = true
				x.infra.Logging[CloudAzure] = append(x.infra.Logging[CloudAzure], Control{Location: blockLocation(block), Detail: "diagnostic setting"})
			}
		}
	}
}

func (x *extractor) azureControls(module *terraform.Module) {
	for _, block := range module.Resources("azurerm_policy_definition") {
		attribute, ok := block.Attr("policy_rule")
		if !ok {
			continue
		}
		if rule, known := module.Text(attribute); known {
			lower := strings.ToLower(rule)
			if strings.Contains(lower, "microsoft.cognitiveservices/accounts") && strings.Contains(lower, `"deny"`) {
				x.infra.Guardrails[CloudAzure] = append(x.infra.Guardrails[CloudAzure], Control{Location: blockLocation(block), Detail: "policy denies Cognitive Services accounts"})
			}
		}
	}
	for _, resourceType := range []string{"azurerm_consumption_budget_subscription", "azurerm_consumption_budget_resource_group", "azurerm_consumption_budget_management_group"} {
		for _, block := range module.Resources(resourceType) {
			budget := Budget{Location: blockLocation(block)}
			for _, filter := range block.Children("filter") {
				for _, dimension := range filter.Children("dimension") {
					if attribute, ok := dimension.Attr("values"); ok {
						budget.Services = append(budget.Services, module.Strings(attribute)...)
					}
				}
			}
			x.infra.Budgets[CloudAzure] = append(x.infra.Budgets[CloudAzure], budget)
		}
	}
	for _, resourceType := range module.ResourceTypes() {
		if strings.HasPrefix(resourceType, "azurerm_") {
			for _, block := range module.Resources(resourceType) {
				x.anchor(CloudAzure, blockLocation(block))
			}
		}
	}
}
