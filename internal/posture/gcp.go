package posture

import (
	"regexp"
	"strings"

	"github.com/ryankshah/jackproof/internal/scan/iac/terraform"
)

const (
	vertexService = "aiplatform.googleapis.com"
	geminiService = "generativelanguage.googleapis.com"
)

var (
	serviceAccountPlaceholder = regexp.MustCompile(`<unresolved:(google_service_account\.[A-Za-z0-9_-]+)\.`)
	gcpScopeByType            = map[string]string{
		"google_project_iam_member":       "project",
		"google_project_iam_binding":      "project",
		"google_folder_iam_member":        "folder",
		"google_folder_iam_binding":       "folder",
		"google_organization_iam_member":  "organization",
		"google_organization_iam_binding": "organization",
	}
)

func (x *extractor) gcp(module *terraform.Module) {
	customRoles := gcpCustomRoles(module)
	for _, resourceType := range sortedKeys(gcpScopeByType) {
		scope := gcpScopeByType[resourceType]
		for _, block := range module.Resources(resourceType) {
			x.gcpBinding(module, block, scope, customRoles)
		}
	}
	x.gcpControls(module)
}

func sortedKeys(values map[string]string) []string {
	return terraform.SortedKeys(values)
}

type gcpCustomRole struct {
	name        string
	permissions []string
}

func gcpCustomRoles(module *terraform.Module) map[string]gcpCustomRole {
	roles := make(map[string]gcpCustomRole)
	for _, resourceType := range []string{"google_project_iam_custom_role", "google_organization_iam_custom_role"} {
		for _, block := range module.Resources(resourceType) {
			role := gcpCustomRole{name: block.Address()}
			if attribute, ok := block.Attr("role_id"); ok {
				if id, known := module.Text(attribute); known {
					role.name = id
				}
			}
			if attribute, ok := block.Attr("permissions"); ok {
				role.permissions = module.Strings(attribute)
			}
			roles[block.Address()] = role
		}
	}
	return roles
}

func (x *extractor) gcpBinding(module *terraform.Module, block *terraform.Block, scope string, customRoles map[string]gcpCustomRole) {
	roleAttribute, ok := block.Attr("role")
	if !ok {
		return
	}
	x.anchor(CloudGCP, blockLocation(block))
	var roleName string
	var permissions []string
	var broad bool
	if reference, isReference := roleAttribute.Reference(); isReference {
		custom, found := customRoles[reference]
		if !found {
			return
		}
		roleName, permissions = custom.name, custom.permissions
	} else if text, known := module.Text(roleAttribute); known {
		roleName = text
		if role, found := x.knowledge.gcpRole(text); found {
			permissions, broad = role.Permissions, role.Broad
		} else if custom, isCustom := customByID(customRoles, text); isCustom {
			permissions = custom.permissions
		}
	}
	if len(permissions) == 0 {
		return
	}
	var members []string
	if attribute, found := block.Attr("member"); found {
		members = module.Strings(attribute)
	}
	if attribute, found := block.Attr("members"); found {
		members = append(members, module.Strings(attribute)...)
	}
	for _, member := range members {
		identity := ""
		if match := serviceAccountPlaceholder.FindStringSubmatch(member); match != nil {
			identity = match[1]
		}
		x.addGrant(Grant{
			Cloud:      CloudGCP,
			Subject:    member,
			Identity:   identity,
			Attachment: blockLocation(block),
			Source:     attributeLocation(block, roleAttribute),
			Actions:    permissions,
			Resources:  []string{scope},
			Admin:      isAdminLabel(member),
			Role:       roleName,
			Broad:      broad,
		})
	}
}

func customByID(roles map[string]gcpCustomRole, text string) (gcpCustomRole, bool) {
	for _, role := range roles {
		if strings.HasSuffix(text, "/roles/"+role.name) {
			return role, true
		}
	}
	return gcpCustomRole{}, false
}

func (x *extractor) gcpControls(module *terraform.Module) {
	for _, block := range module.Resources("google_project_service") {
		attribute, ok := block.Attr("service")
		if !ok {
			continue
		}
		switch service, _ := module.Text(attribute); service {
		case vertexService:
			x.infra.Usage = append(x.infra.Usage, Usage{Service: "vertex-ai", Location: blockLocation(block)})
		case geminiService:
			x.infra.Usage = append(x.infra.Usage, Usage{Service: "gemini-api", Location: blockLocation(block)})
		}
	}

	for _, resourceType := range []string{"google_org_policy_policy", "google_organization_policy", "google_folder_organization_policy", "google_project_organization_policy"} {
		for _, block := range module.Resources(resourceType) {
			for _, field := range []string{"name", "constraint"} {
				if attribute, ok := block.Attr(field); ok {
					if text, known := module.Text(attribute); known && strings.Contains(text, "gcp.restrictServiceUsage") {
						x.infra.Guardrails[CloudGCP] = append(x.infra.Guardrails[CloudGCP], Control{Location: blockLocation(block), Detail: "organization policy restricts service usage"})
					}
				}
			}
		}
	}

	for _, block := range module.Resources("google_project_iam_audit_config") {
		attribute, ok := block.Attr("service")
		if !ok {
			continue
		}
		service, _ := module.Text(attribute)
		if service != "allServices" && service != vertexService {
			continue
		}
		logTypes := make(map[string]bool)
		for _, config := range block.Children("audit_log_config") {
			if typeAttribute, found := config.Attr("log_type"); found {
				if logType, known := module.Text(typeAttribute); known {
					logTypes[logType] = true
				}
			}
		}
		if logTypes["DATA_READ"] && logTypes["DATA_WRITE"] {
			x.infra.Logging[CloudGCP] = append(x.infra.Logging[CloudGCP], Control{Location: blockLocation(block), Detail: "Data Access audit logs for Vertex AI"})
		}
	}

	for _, block := range module.Resources("google_billing_budget") {
		budget := Budget{Location: blockLocation(block)}
		for _, filter := range block.Children("budget_filter") {
			if attribute, ok := filter.Attr("services"); ok {
				budget.Services = append(budget.Services, module.Strings(attribute)...)
			}
		}
		x.infra.Budgets[CloudGCP] = append(x.infra.Budgets[CloudGCP], budget)
	}

	for _, block := range module.Resources("google_service_usage_consumer_quota_override") {
		if attribute, ok := block.Attr("service"); ok {
			if service, known := module.Text(attribute); known && (service == vertexService || service == geminiService) {
				x.infra.Quotas[CloudGCP] = append(x.infra.Quotas[CloudGCP], Control{Location: blockLocation(block), Detail: "consumer quota override"})
			}
		}
	}

	for _, resourceType := range module.ResourceTypes() {
		if strings.HasPrefix(resourceType, "google_") {
			for _, block := range module.Resources(resourceType) {
				x.anchor(CloudGCP, blockLocation(block))
			}
		}
	}
}
