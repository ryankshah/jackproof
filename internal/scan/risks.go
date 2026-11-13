package scan

import (
	"fmt"
	"strings"

	"github.com/ryankshah/jackproof/internal/finding"
	"github.com/ryankshah/jackproof/internal/graph"
)

func (r *run) evaluateRisks() {
	r.crossEnvironment()
	r.untrustedWorkloads()
	r.sharedSinks()
	r.staticCloudKeys()
}

func (r *run) describe(credential graph.Credential) string {
	label := credential.Name
	if credential.Kind == graph.KindLiteral {
		label = credential.Redacted
	}
	return fmt.Sprintf("%s credential %s", r.providerName(credential.Provider), label)
}

func (r *run) crossEnvironment() {
	for _, credential := range r.graph.Credentials() {
		environments := r.graph.Environments(credential.Key)
		if len(environments) < 2 {
			continue
		}
		var evidence []finding.Evidence
		covered := make(map[string]bool)
		for _, edge := range r.graph.EdgesOf(credential.Key) {
			holder, _ := r.graph.Holder(edge.Holder)
			if holder.Environment == "" || covered[holder.Environment] {
				continue
			}
			covered[holder.Environment] = true
			evidence = append(evidence, r.evidenceAt(edge.Location.Path, edge.Location.Line))
		}
		confidence := finding.ConfidenceHigh
		var flags []finding.Flag
		var unproven []string
		if credential.Kind == graph.KindReference {
			confidence = finding.ConfidenceMedium
			flags = []finding.Flag{finding.FlagInferred}
			unproven = []string{"Whether the reference resolves to the same value in each environment."}
		}
		r.emit(findingSpec{
			rule:       ruleCrossEnvironment,
			title:      fmt.Sprintf("%s is used in %s", r.describe(credential), strings.Join(environments, " and ")),
			method:     finding.MethodIaCParse,
			confidence: confidence,
			flags:      flags,
			unproven:   unproven,
			evidence:   evidence,
		})
	}
}

func (r *run) untrustedWorkloads() {
	reported := make(map[string]bool)
	for _, credential := range r.graph.Credentials() {
		for _, edge := range r.graph.EdgesOf(credential.Key) {
			holder, _ := r.graph.Holder(edge.Holder)
			pair := credential.Key + "|" + holder.ID
			if !holder.Untrusted || reported[pair] {
				continue
			}
			reported[pair] = true

			confidence := finding.ConfidenceMedium
			flags := []finding.Flag{finding.FlagInferred}
			unproven := []string{"Whether this workload runs untrusted or user-supplied code. " + holder.UntrustedReason + "."}
			switch {
			case holder.UntrustedProven:
				confidence = finding.ConfidenceHigh
				flags = nil
				unproven = []string{"Whether the pull request author controls code that runs in this job beyond what the checkout step shows."}
			case holder.Kind == graph.HolderGitHubJob:
				unproven = []string{"No checkout of pull request code was found in this job, so it is not shown that untrusted code runs with the secret."}
			}
			r.emit(findingSpec{
				rule:       ruleUntrustedWorkload,
				title:      fmt.Sprintf("%s reaches %s, which may run untrusted code", r.describe(credential), holder.Name),
				method:     finding.MethodIaCParse,
				confidence: confidence,
				flags:      flags,
				unproven:   unproven,
				evidence: []finding.Evidence{
					r.evidenceAt(edge.Location.Path, edge.Location.Line),
					r.evidenceAt(holder.Location.Path, holder.Location.Line),
				},
			})
		}
	}
}

func (r *run) sharedSinks() {
	reported := make(map[string]bool)
	for _, credential := range r.graph.Credentials() {
		for _, edge := range r.graph.EdgesOf(credential.Key) {
			holder, _ := r.graph.Holder(edge.Holder)
			pair := credential.Key + "|" + holder.ID
			if !edge.Plain || len(holder.Sinks) == 0 || reported[pair] {
				continue
			}
			reported[pair] = true
			sink := holder.Sinks[0]
			unproven := "Whether the reporter captures environment variables."
			if sink.Kind == graph.SinkEnvDump {
				unproven = "Whether log masking prevents the value from appearing in the output."
			}
			r.emit(findingSpec{
				rule:       ruleSharedSink,
				title:      fmt.Sprintf("%s is in the environment of %s, which has a %s", r.describe(credential), holder.Name, sink.Kind),
				method:     finding.MethodIaCParse,
				confidence: finding.ConfidenceMedium,
				flags:      []finding.Flag{finding.FlagInferred},
				unproven:   []string{unproven},
				evidence: []finding.Evidence{
					r.evidenceAt(edge.Location.Path, edge.Location.Line),
					r.evidenceAt(sink.Location.Path, sink.Location.Line),
				},
			})
		}
	}
}

func (r *run) staticCloudKeys() {
	reported := make(map[string]bool)
	for _, credential := range r.graph.Credentials() {
		if !cloudProviders[credential.Provider] {
			continue
		}
		for _, edge := range r.graph.EdgesOf(credential.Key) {
			holder, _ := r.graph.Holder(edge.Holder)
			if holder.Kind == graph.HolderCode || holder.Kind == graph.HolderNotebook {
				continue
			}
			pair := credential.Provider + "|" + holder.ID
			if reported[pair] {
				continue
			}
			reported[pair] = true

			confidence := finding.ConfidenceHigh
			var flags []finding.Flag
			var unproven []string
			if holder.Kind != graph.HolderGitHubJob && holder.Kind != graph.HolderKubernetes {
				confidence = finding.ConfidenceMedium
				flags = []finding.Flag{finding.FlagInferred}
				unproven = []string{"Whether the platform that runs this workload can issue role-based or federated credentials."}
			}
			r.emit(findingSpec{
				rule:       ruleStaticCloudKey,
				title:      fmt.Sprintf("%s is a long-lived key delivered to %s", r.describe(credential), holder.Name),
				method:     finding.MethodIaCParse,
				confidence: confidence,
				flags:      flags,
				unproven:   unproven,
				evidence:   []finding.Evidence{r.evidenceAt(edge.Location.Path, edge.Location.Line)},
			})
		}
	}
}
