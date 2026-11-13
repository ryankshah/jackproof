package exposure

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/ryankshah/jackproof/internal/graph"
)

const (
	PhaseCreate  = "create"
	PhaseUpdate  = "update"
	PhaseRebuild = "rebuild"
	PhaseRestart = "restart"
	PhaseVerify  = "verify"
	PhaseRevoke  = "revoke"
	PhaseCleanup = "cleanup"

	revocationStatement = "Deleting a stored secret does not revoke it. The old credential stays valid until the provider revokes it."
)

var cloudProviders = map[string]bool{"aws": true, "gcp": true}

type Blast struct {
	Holders      int      `json:"holders"`
	Environments []string `json:"environments"`
	Untrusted    int      `json:"untrusted_holders"`
	Score        int      `json:"score"`
}

type StepTarget struct {
	Path   string `json:"path,omitempty"`
	Line   int    `json:"line,omitempty"`
	Detail string `json:"detail"`
}

type Step struct {
	Order   int          `json:"order"`
	Phase   string       `json:"phase"`
	Action  string       `json:"action"`
	Targets []StepTarget `json:"targets,omitempty"`
}

type CredentialPlan struct {
	Label    string `json:"label"`
	Provider string `json:"provider,omitempty"`
	Found    bool   `json:"found"`
	Blast    Blast  `json:"blast_radius"`
	Reach    string `json:"reach,omitempty"`
	Steps    []Step `json:"steps"`
}

type Plan struct {
	Statement   string           `json:"statement"`
	Credentials []CredentialPlan `json:"credentials"`
}

func BuildPlan(exposures []Exposure) Plan {
	plan := Plan{Statement: revocationStatement}
	for _, exposure := range exposures {
		plan.Credentials = append(plan.Credentials, planFor(exposure))
	}
	sort.SliceStable(plan.Credentials, func(i, j int) bool {
		a, b := plan.Credentials[i], plan.Credentials[j]
		if a.Blast.Score != b.Blast.Score {
			return a.Blast.Score > b.Blast.Score
		}
		return a.Label < b.Label
	})
	return plan
}

func planFor(exposure Exposure) CredentialPlan {
	holders := distinctHolders(exposure.Locations)
	environments := distinctEnvironments(holders)
	untrusted := 0
	for _, holder := range holders {
		if holder.untrusted {
			untrusted++
		}
	}
	score := len(holders) + 3*len(environments) + 5*untrusted
	if cloudProviders[exposure.Provider] {
		score += 3
	}
	plan := CredentialPlan{
		Label:    exposure.Target.Label(),
		Provider: exposure.Provider,
		Found:    len(exposure.Locations) > 0,
		Blast:    Blast{Holders: len(holders), Environments: environments, Untrusted: untrusted, Score: score},
		Reach:    exposure.Reach,
	}
	builder := &stepBuilder{}
	builder.add(PhaseCreate, createAction(exposure.Provider, environments), nil)
	if targets := updateTargets(exposure.Locations); len(targets) > 0 {
		builder.add(PhaseUpdate, "Replace the stored value at each location. Update CI settings, secret managers and platform secrets before the files that deploy from them.", targets)
	}
	if targets := rebuildTargets(exposure.Locations); len(targets) > 0 {
		builder.add(PhaseRebuild, "Rebuild each image that bakes in the credential and push new tags. Old image layers still contain the exposed value: delete the old tags and expire cached layers.", targets)
	}
	if targets := restartTargets(holders); len(targets) > 0 {
		builder.add(PhaseRestart, "Restart or redeploy the workloads in this order. Lower environments come first, so a failed rotation shows up before it reaches production.", targets)
	}
	builder.add(PhaseVerify, "Confirm that each workload authenticates with the replacement credential. Check the provider usage log for requests that still use the old credential.", nil)
	builder.add(PhaseRevoke, "Revoke the old credential at the provider once no workload uses it. "+revocationStatement, nil)
	if hasLiteral(exposure.Locations) {
		builder.add(PhaseCleanup, "Remove the literal value from version control history and treat every fork and clone as exposed. Removing the line from the current files does not remove it from history.", nil)
	}
	plan.Steps = builder.steps
	return plan
}

type stepBuilder struct {
	steps []Step
}

func (b *stepBuilder) add(phase, action string, targets []StepTarget) {
	b.steps = append(b.steps, Step{Order: len(b.steps) + 1, Phase: phase, Action: action, Targets: targets})
}

func createAction(provider string, environments []string) string {
	subject := "replacement credential"
	if provider != "" {
		subject = fmt.Sprintf("replacement %s credential", provider)
	}
	if len(environments) > 1 {
		return fmt.Sprintf("Create one %s for each environment (%s). Do not reuse one new credential across environments.", subject, strings.Join(environments, ", "))
	}
	return fmt.Sprintf("Create one %s before changing anything that uses the old one.", subject)
}

func updateTargets(locations []Location) []StepTarget {
	var targets []StepTarget
	for _, location := range locations {
		if location.Role == roleInjection && location.Delivery != string(graph.DeliverySecretRef) && location.Delivery != string(graph.DeliveryEnvFile) {
			continue
		}
		detail := location.Role
		if location.Holder != "" {
			detail = fmt.Sprintf("%s, used by %s", location.Role, location.Holder)
		}
		targets = append(targets, StepTarget{Path: location.Path, Line: location.Line, Detail: detail})
	}
	return targets
}

func rebuildTargets(locations []Location) []StepTarget {
	var targets []StepTarget
	for _, location := range locations {
		if location.Delivery == string(graph.DeliveryImageEnv) || location.Delivery == string(graph.DeliveryImageCopy) || location.Delivery == string(graph.DeliveryBuildArg) {
			targets = append(targets, StepTarget{Path: location.Path, Line: location.Line, Detail: "image build"})
		}
	}
	return targets
}

type holderEntry struct {
	name        string
	kind        string
	environment string
	path        string
	line        int
	untrusted   bool
}

func distinctHolders(locations []Location) []holderEntry {
	seen := make(map[string]bool)
	var holders []holderEntry
	for _, location := range locations {
		if location.Holder == "" {
			continue
		}
		key := location.HolderKind + "|" + location.Path + "|" + location.Holder
		if seen[key] {
			continue
		}
		seen[key] = true
		holders = append(holders, holderEntry{
			name: location.Holder, kind: location.HolderKind, environment: location.Environment,
			path: location.Path, line: location.Line, untrusted: location.Untrusted,
		})
	}
	return holders
}

func distinctEnvironments(holders []holderEntry) []string {
	seen := make(map[string]bool)
	var environments []string
	for _, holder := range holders {
		if holder.environment != "" && !seen[holder.environment] {
			seen[holder.environment] = true
			environments = append(environments, holder.environment)
		}
	}
	sort.Strings(environments)
	return environments
}

func environmentRank(environment string) int {
	switch strings.ToLower(environment) {
	case "prod", "production":
		return 2
	case "":
		return 1
	}
	return 0
}

func restartTargets(holders []holderEntry) []StepTarget {
	ordered := append([]holderEntry(nil), holders...)
	sort.SliceStable(ordered, func(i, j int) bool {
		a, b := ordered[i], ordered[j]
		if environmentRank(a.environment) != environmentRank(b.environment) {
			return environmentRank(a.environment) < environmentRank(b.environment)
		}
		if a.environment != b.environment {
			return a.environment < b.environment
		}
		if a.kind != b.kind {
			return a.kind < b.kind
		}
		return a.name < b.name
	})
	targets := make([]StepTarget, 0, len(ordered))
	for _, holder := range ordered {
		detail := fmt.Sprintf("%s %s", holder.kind, holder.name)
		if holder.environment != "" {
			detail += fmt.Sprintf(" (%s)", holder.environment)
		}
		targets = append(targets, StepTarget{Path: holder.path, Line: holder.line, Detail: detail})
	}
	return targets
}

func hasLiteral(locations []Location) bool {
	for _, location := range locations {
		if location.Role == roleDefinition {
			return true
		}
	}
	return false
}

func (p Plan) WriteMarkdown(w io.Writer) error {
	var builder strings.Builder
	builder.WriteString(p.Statement + "\n")
	for _, credential := range p.Credentials {
		fmt.Fprintf(&builder, "\n### %s\n\n", capitalize(credential.Label))
		if !credential.Found {
			builder.WriteString("No location was found in the scanned paths. Revoke it at the provider anyway, and search the places this scan did not cover.\n")
		}
		fmt.Fprintf(&builder, "Blast radius: %d %s, %d %s", credential.Blast.Holders, pluralize("workload", credential.Blast.Holders), len(credential.Blast.Environments), pluralize("environment", len(credential.Blast.Environments)))
		if len(credential.Blast.Environments) > 0 {
			builder.WriteString(" (" + strings.Join(credential.Blast.Environments, ", ") + ")")
		}
		if credential.Blast.Untrusted > 0 {
			fmt.Fprintf(&builder, ", %d that may run untrusted code", credential.Blast.Untrusted)
		}
		builder.WriteString(".\n")
		if credential.Reach != "" {
			builder.WriteString("If it is abused: " + credential.Reach + "\n")
		}
		builder.WriteString("\n")
		for _, step := range credential.Steps {
			fmt.Fprintf(&builder, "%d. **%s.** %s\n", step.Order, capitalize(step.Phase), step.Action)
			for _, target := range step.Targets {
				if target.Path != "" {
					fmt.Fprintf(&builder, "   - `%s:%d`: %s\n", target.Path, target.Line, target.Detail)
				} else {
					fmt.Fprintf(&builder, "   - %s\n", target.Detail)
				}
			}
		}
	}
	if _, err := io.WriteString(w, builder.String()); err != nil {
		return fmt.Errorf("write rotation plan: %w", err)
	}
	return nil
}
