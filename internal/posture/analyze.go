package posture

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/ryankshah/jackproof/internal/config"
	"github.com/ryankshah/jackproof/internal/finding"
	"github.com/ryankshah/jackproof/internal/rules"
)

const (
	ruleEnable    = "JP-POS-001"
	ruleGuardrail = "JP-POS-002"
	ruleLogging   = "JP-POS-003"
	ruleBudget    = "JP-POS-004"
	ruleQuota     = "JP-POS-005"
	ruleWildcard  = "JP-POS-006"
	ruleKeys      = "JP-POS-007"

	maxExcerpt = 160
)

var requiredRules = []string{ruleEnable, ruleGuardrail, ruleLogging, ruleBudget, ruleQuota, ruleWildcard, ruleKeys}

var clouds = []Cloud{CloudAWS, CloudGCP, CloudAzure}

type analyzer struct {
	cfg       *config.Config
	rules     *rules.Catalogue
	knowledge *Knowledge
	infra     *Infra
	lines     map[string][]string
	findings  []finding.Finding
	seen      map[string]bool
}

func Analyze(infra *Infra, sources []Source, cfg *config.Config, ruleSet *rules.Catalogue, knowledge *Knowledge) ([]finding.Finding, error) {
	for _, id := range requiredRules {
		if _, ok := ruleSet.Get(id); !ok {
			return nil, fmt.Errorf("rule catalogue is missing %s", id)
		}
	}
	a := &analyzer{
		cfg: cfg, rules: ruleSet, knowledge: knowledge, infra: infra,
		lines: make(map[string][]string, len(sources)),
		seen:  make(map[string]bool),
	}
	for _, source := range sources {
		a.lines[source.Path] = strings.Split(strings.ReplaceAll(string(source.Data), "\r\n", "\n"), "\n")
	}
	a.enableAccess()
	a.guardrails()
	a.logging()
	a.budgets()
	a.quotas()
	a.wildcardInvoke()
	a.keyCreation()
	finding.Sort(a.findings)
	return a.findings, nil
}

type spec struct {
	rule       string
	method     finding.Method
	confidence finding.Confidence
	flags      []finding.Flag
	unproven   []string
	title      string
	snippet    string
	locations  []Location
}

func (a *analyzer) emit(s spec) {
	rule, _ := a.rules.Get(s.rule)
	evidence := make([]finding.Evidence, 0, len(s.locations))
	for _, location := range s.locations {
		if location.Path == "" || location.Line < 1 {
			continue
		}
		evidence = append(evidence, finding.Evidence{Path: location.Path, StartLine: location.Line, EndLine: location.Line, Excerpt: a.excerpt(location)})
	}
	if len(evidence) == 0 {
		return
	}
	f := rule.NewFinding(s.method, s.confidence, evidence...)
	f.Title = s.title
	f.Flags = append(f.Flags, s.flags...)
	f.Unproven = s.unproven
	if s.snippet != "" {
		f.Remediation = rule.Remediation + "\n\n" + s.snippet
	}
	if a.seen[f.ID] {
		return
	}
	a.seen[f.ID] = true
	a.findings = append(a.findings, f)
}

func (a *analyzer) excerpt(location Location) string {
	lines := a.lines[location.Path]
	if location.Line < 1 || location.Line > len(lines) {
		return ""
	}
	text := strings.TrimSpace(lines[location.Line-1])
	if len(text) > maxExcerpt {
		return text[:maxExcerpt] + "..."
	}
	return text
}

func (a *analyzer) serviceActions(capabilityName string, cloud Cloud, service string) []string {
	var actions []string
	for _, entry := range a.knowledge.Capabilities {
		if entry.Name == capabilityName && entry.Cloud == cloud && entry.Service == service {
			actions = append(actions, entry.Actions...)
		}
	}
	return actions
}

func (a *analyzer) expects(environment, service string) (expected, configured bool) {
	providers, configured := a.cfg.ExpectedProvidersFor(environment)
	if environment == "" || !configured {
		return false, false
	}
	return slices.Contains(providers, service), true
}

func (a *analyzer) cloudOf(service string) Cloud {
	for _, entry := range a.knowledge.Services {
		if entry.ID == service {
			return entry.Cloud
		}
	}
	return ""
}

func (a *analyzer) enableAccess() {
	for _, grant := range a.infra.Grants {
		if grant.Admin {
			continue
		}
		var missing []string
		var matched []string
		configured := false
		for _, service := range a.knowledge.servicesFor(capabilityEnable, grant.Cloud) {
			actions := matchedActions(grant.Actions, a.serviceActions(capabilityEnable, grant.Cloud, service))
			if len(actions) == 0 {
				continue
			}
			expected, isConfigured := a.expects(grant.Environment, service)
			if expected {
				continue
			}
			configured = configured || isConfigured
			missing = append(missing, a.knowledge.serviceName(service))
			matched = append(matched, actions...)
		}
		if len(missing) == 0 {
			continue
		}
		confidence := finding.ConfidenceHigh
		var flags []finding.Flag
		var unproven []string
		if configured {
			flags = []finding.Flag{finding.FlagConfigImplied}
		} else {
			confidence = finding.ConfidenceMedium
			unproven = append(unproven, "jackproof.yaml has no expected_providers entry for this environment, so it is not known whether models are expected here.")
		}
		if onlyGeneric(matched) {
			confidence = finding.ConfidenceMedium
			unproven = append(unproven, "The matched permission is not specific to model services: "+strings.Join(uniqueSorted(matched), ", ")+".")
		}
		a.emit(spec{
			rule:       ruleEnable,
			method:     finding.MethodPolicyEval,
			confidence: confidence,
			flags:      flags,
			unproven:   unproven,
			title:      fmt.Sprintf("%s can enable %s", grant.Subject, strings.Join(uniqueSorted(missing), " and ")),
			snippet:    guardrailSnippet(grant.Cloud),
			locations:  []Location{grant.Attachment, grant.Source},
		})
	}
}

func onlyGeneric(actions []string) bool {
	for _, action := range actions {
		if action != "aws-marketplace:Subscribe" && action != "serviceusage.services.enable" {
			return false
		}
	}
	return true
}

func uniqueSorted(values []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}

func (a *analyzer) servicesOf(cloud Cloud) []string {
	var services []string
	for _, entry := range a.knowledge.Services {
		if entry.Cloud == cloud {
			services = append(services, entry.ID)
		}
	}
	return services
}

func (a *analyzer) everywhereExpected(cloud Cloud) bool {
	if len(a.cfg.ExpectedProviders) == 0 {
		return false
	}
	for environment := range a.cfg.Environments {
		for _, service := range a.servicesOf(cloud) {
			if expected, _ := a.expects(environment, service); !expected {
				return false
			}
		}
	}
	return len(a.cfg.Environments) > 0
}

func (a *analyzer) guardrails() {
	for _, cloud := range clouds {
		anchor, present := a.infra.Anchors[cloud]
		if !present || len(a.infra.Guardrails[cloud]) > 0 || a.everywhereExpected(cloud) {
			continue
		}
		a.emit(spec{
			rule:       ruleGuardrail,
			method:     finding.MethodPolicyEval,
			confidence: finding.ConfidenceMedium,
			flags:      []finding.Flag{finding.FlagIncomplete},
			unproven:   []string{"Whether a guardrail is defined outside the scanned paths, for example in the organization management account."},
			title:      fmt.Sprintf("No %s guardrail denies model services in the scanned infrastructure code", strings.ToUpper(string(cloud))),
			snippet:    guardrailSnippet(cloud),
			locations:  []Location{anchor},
		})
	}
}

func (a *analyzer) modelEvidence(cloud Cloud) ([]Location, bool) {
	for _, usage := range a.infra.Usage {
		if a.cloudOf(usage.Service) == cloud {
			return []Location{usage.Location}, true
		}
	}
	anchor, anchored := a.infra.Anchors[cloud]
	for _, grant := range a.infra.Grants {
		if grant.Admin || grant.Cloud != cloud || len(matchedActions(grant.Actions, a.knowledge.capabilityActions(capabilityInvoke, cloud))) == 0 {
			continue
		}
		if anchored {
			return []Location{anchor, grant.Attachment}, true
		}
		return []Location{grant.Attachment}, true
	}
	for _, environment := range sortedEnvironments(a.cfg.ExpectedProviders) {
		for _, service := range a.cfg.ExpectedProviders[environment] {
			if a.cloudOf(service) == cloud && anchored {
				return []Location{anchor}, true
			}
		}
	}
	return nil, false
}

func sortedEnvironments(values map[string][]string) []string {
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (a *analyzer) logging() {
	for _, cloud := range clouds {
		for _, control := range a.infra.LoggingOff[cloud] {
			a.emit(spec{
				rule:       ruleLogging,
				method:     finding.MethodIaCParse,
				confidence: finding.ConfidenceHigh,
				title:      "Model invocation logging is configured with every delivery type turned off",
				snippet:    loggingSnippet(cloud),
				locations:  []Location{control.Location},
			})
		}
		if locations, inUse := a.modelEvidence(cloud); inUse && len(a.infra.Logging[cloud]) == 0 && len(a.infra.LoggingOff[cloud]) == 0 && cloud != CloudAzure {
			a.emit(spec{
				rule:       ruleLogging,
				method:     finding.MethodIaCParse,
				confidence: finding.ConfidenceMedium,
				flags:      []finding.Flag{finding.FlagIncomplete},
				unproven:   []string{"Whether logging is configured outside the scanned paths, for example in the console or another repository."},
				title:      fmt.Sprintf("Models are in use on %s and no invocation logging is configured in the scanned code", strings.ToUpper(string(cloud))),
				snippet:    loggingSnippet(cloud),
				locations:  locations,
			})
		}
	}
	for _, account := range a.infra.Accounts {
		if !account.Monitored {
			a.emit(spec{
				rule:       ruleLogging,
				method:     finding.MethodIaCParse,
				confidence: finding.ConfidenceMedium,
				flags:      []finding.Flag{finding.FlagIncomplete},
				unproven:   []string{"Whether a diagnostic setting exists outside the scanned paths."},
				title:      fmt.Sprintf("Azure OpenAI account %s has no diagnostic setting", account.Address),
				snippet:    azureLoggingSnippet,
				locations:  []Location{account.Location},
			})
		}
	}
	toggles := a.knowledge.capabilityActions(capabilityLogging, CloudAWS)
	for _, grant := range a.infra.Grants {
		if grant.Admin || grant.Cloud != CloudAWS {
			continue
		}
		matched := matchedActions(grant.Actions, toggles)
		if len(matched) == 0 {
			continue
		}
		a.emit(spec{
			rule:       ruleLogging,
			method:     finding.MethodPolicyEval,
			confidence: finding.ConfidenceHigh,
			title:      fmt.Sprintf("%s can change or delete the Bedrock invocation logging configuration", grant.Subject),
			snippet:    awsLoggingSnippet,
			locations:  []Location{grant.Attachment, grant.Source},
		})
	}
}

func (a *analyzer) modelServiceTerms(cloud Cloud) []string {
	var terms []string
	for _, entry := range a.knowledge.Services {
		if entry.Cloud == cloud {
			terms = append(terms, entry.BudgetTerms...)
		}
	}
	return terms
}

func (a *analyzer) budgets() {
	for _, cloud := range clouds {
		locations, inUse := a.modelEvidence(cloud)
		if !inUse || a.budgetCovers(cloud) {
			continue
		}
		a.emit(spec{
			rule:       ruleBudget,
			method:     finding.MethodIaCParse,
			confidence: finding.ConfidenceMedium,
			flags:      []finding.Flag{finding.FlagIncomplete},
			unproven:   []string{"Whether a budget exists outside the scanned paths, for example on the billing account."},
			title:      fmt.Sprintf("No %s budget in the scanned code covers model spend", strings.ToUpper(string(cloud))),
			snippet:    budgetSnippet(cloud),
			locations:  locations,
		})
	}
}

func (a *analyzer) budgetCovers(cloud Cloud) bool {
	terms := a.modelServiceTerms(cloud)
	for _, budget := range a.infra.Budgets[cloud] {
		if len(budget.Services) == 0 {
			return true
		}
		for _, service := range budget.Services {
			lower := strings.ToLower(service)
			for _, term := range terms {
				if strings.Contains(lower, term) {
					return true
				}
			}
		}
	}
	return false
}

func (a *analyzer) quotas() {
	for _, cloud := range clouds {
		if cloud == CloudAzure {
			continue
		}
		locations, inUse := a.modelEvidence(cloud)
		if !inUse || len(a.infra.Quotas[cloud]) > 0 {
			continue
		}
		a.emit(spec{
			rule:       ruleQuota,
			method:     finding.MethodIaCParse,
			confidence: finding.ConfidenceLow,
			flags:      []finding.Flag{finding.FlagIncomplete},
			unproven:   []string{"Whether a quota is set outside the scanned paths, and what the service default is."},
			title:      fmt.Sprintf("No %s quota or rate limit for model services is set in the scanned code", strings.ToUpper(string(cloud))),
			snippet:    quotaSnippet(cloud),
			locations:  locations,
		})
	}
	for _, account := range a.infra.Accounts {
		if len(account.Deployments) == 0 {
			continue
		}
		a.emit(spec{
			rule:       ruleQuota,
			method:     finding.MethodIaCParse,
			confidence: finding.ConfidenceMedium,
			unproven:   []string{"What the default capacity is for the model and region."},
			title:      fmt.Sprintf("Azure OpenAI deployments on %s set no capacity", account.Address),
			snippet:    azureQuotaSnippet,
			locations:  account.Deployments,
		})
	}
}

func hasWildcardAction(actions []string, service string) bool {
	for _, action := range actions {
		if action == "*" || strings.EqualFold(action, service+":*") {
			return true
		}
	}
	return false
}

func hasWildcardResource(resources []string) bool {
	for _, resource := range resources {
		if resource == "*" || strings.Contains(resource, "foundation-model/*") {
			return true
		}
	}
	return false
}

func (a *analyzer) wildcardInvoke() {
	for _, grant := range a.infra.Grants {
		if grant.Admin {
			continue
		}
		matched := matchedActions(grant.Actions, a.knowledge.capabilityActions(capabilityInvoke, grant.Cloud))
		if len(matched) == 0 {
			continue
		}
		switch grant.Cloud {
		case CloudAWS:
			a.awsWildcard(grant)
		case CloudGCP:
			if grant.Broad && strings.HasPrefix(grant.Subject, "serviceAccount:") {
				a.emit(spec{
					rule:       ruleWildcard,
					method:     finding.MethodPolicyEval,
					confidence: finding.ConfidenceMedium,
					flags:      []finding.Flag{finding.FlagInferred},
					unproven:   []string{"Which models the service account uses in practice."},
					title:      fmt.Sprintf("%s holds %s, which allows invoking every model in the %s", grant.Subject, grant.Role, grant.Resources[0]),
					snippet:    "Grant roles/aiplatform.user on the specific project that serves models, and remove the broad role.",
					locations:  []Location{grant.Attachment, grant.Source},
				})
			}
		case CloudAzure:
			if grant.Broad || !strings.Contains(strings.Join(grant.Resources, " "), "/resourceGroups/") {
				a.emit(spec{
					rule:       ruleWildcard,
					method:     finding.MethodPolicyEval,
					confidence: finding.ConfidenceMedium,
					flags:      []finding.Flag{finding.FlagInferred},
					unproven:   []string{"Whether the scope covers resources beyond the Azure OpenAI accounts the principal needs."},
					title:      fmt.Sprintf("%s holds %s at a broad scope", grant.Subject, grant.Role),
					snippet:    "Assign the role at the scope of the single Azure OpenAI account, not the subscription.",
					locations:  []Location{grant.Attachment},
				})
			}
		}
	}
}

func (a *analyzer) awsWildcard(grant Grant) {
	wildcardAction := hasWildcardAction(grant.Actions, "bedrock")
	wildcardResource := hasWildcardResource(grant.Resources)
	if !wildcardAction && !wildcardResource {
		return
	}
	var reasons []string
	if wildcardAction {
		reasons = append(reasons, "a wildcard action")
	}
	if wildcardResource {
		reasons = append(reasons, "a wildcard resource")
	}
	var flags []finding.Flag
	var unproven []string
	if grant.Unattached {
		flags = []finding.Flag{finding.FlagIncomplete}
		unproven = []string{"Which identities use this policy is not shown in the scanned code."}
	}
	a.emit(spec{
		rule:       ruleWildcard,
		method:     finding.MethodPolicyEval,
		confidence: finding.ConfidenceHigh,
		flags:      flags,
		unproven:   unproven,
		title:      fmt.Sprintf("%s can invoke any Bedrock model through %s", grant.Subject, strings.Join(reasons, " and ")),
		snippet:    awsInvokeSnippet,
		locations:  []Location{grant.Attachment, grant.Source},
	})
}

func (a *analyzer) modelCapable(cloud Cloud) map[string]string {
	capable := make(map[string]string)
	invoke := a.knowledge.capabilityActions(capabilityInvoke, cloud)
	for _, grant := range a.infra.Grants {
		if grant.Cloud == cloud && grant.Identity != "" && len(matchedActions(grant.Actions, invoke)) > 0 {
			capable[grant.Identity] = grant.Subject
		}
	}
	return capable
}

func (a *analyzer) keyCreation() {
	for _, cloud := range []Cloud{CloudAWS, CloudGCP} {
		capable := a.modelCapable(cloud)
		createActions := a.knowledge.capabilityActions(capabilityKeys, cloud)
		for _, grant := range a.infra.Grants {
			if grant.Cloud != cloud || grant.Admin || len(matchedActions(grant.Actions, createActions)) == 0 {
				continue
			}
			target, reachable := keyTarget(cloud, grant, capable)
			if !reachable {
				continue
			}
			a.emit(spec{
				rule:       ruleKeys,
				method:     finding.MethodPolicyEval,
				confidence: finding.ConfidenceMedium,
				flags:      []finding.Flag{finding.FlagInferred},
				unproven:   []string{"Whether the principals that can receive a new key are the ones used for model access in production."},
				title:      fmt.Sprintf("%s can create long-lived keys for %s", grant.Subject, target),
				snippet:    keyDenySnippet(cloud),
				locations:  []Location{grant.Attachment, grant.Source},
			})
		}
	}
}

func keyTarget(cloud Cloud, grant Grant, capable map[string]string) (string, bool) {
	if len(capable) == 0 {
		return "", false
	}
	if cloud == CloudGCP {
		return "model-capable service accounts", true
	}
	for _, resource := range grant.Resources {
		if resource == "*" || strings.HasSuffix(resource, ":user/*") {
			return "any IAM user, including model-capable users", true
		}
		for address, label := range capable {
			if strings.Contains(resource, address) || strings.HasSuffix(resource, "user/"+label) {
				return label, true
			}
		}
	}
	return "", false
}
