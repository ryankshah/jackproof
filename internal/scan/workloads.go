package scan

import (
	"cmp"
	"fmt"
	"github.com/ryankshah/jackproof/internal/secret"
	"path"
	"strings"

	"github.com/ryankshah/jackproof/internal/finding"
	"github.com/ryankshah/jackproof/internal/graph"
	"github.com/ryankshah/jackproof/internal/scan/iac"
	"github.com/ryankshah/jackproof/internal/scan/lang"
)

var actionInputProviders = map[string]string{
	"aws-access-key-id":     "aws",
	"aws-secret-access-key": "aws",
	"credentials_json":      "gcp",
}

var cloudProviders = map[string]bool{"aws": true, "gcp": true}

func (r *run) processStructure(file *sourceFile, hits []literalHit) {
	var workloads []iac.Workload
	var err error
	switch file.kind {
	case kindCompose:
		workloads, err = iac.ParseCompose(file.path, file.data)
	case kindKubernetes:
		workloads, err = iac.ParseKubernetes(file.path, file.data)
	case kindActions:
		workloads, err = iac.ParseActions(file.path, file.data)
	case kindDockerfile:
		workloads = []iac.Workload{iac.ParseDockerfile(file.path, file.data)}
	case kindDevcontainer:
		var workload iac.Workload
		workload, err = iac.ParseDevcontainer(file.path, file.data)
		workloads = []iac.Workload{workload}
	case lang.Go, lang.Python, lang.JavaScript, kindNotebook:
		r.processCode(file, hits)
		return
	default:
		return
	}
	if err != nil {
		r.coverage.AddSkipped(file.path, fmt.Sprintf("structure not analysed: %v", err))
		return
	}
	for _, workload := range workloads {
		r.addWorkload(file, workload)
		if file.kind == kindDockerfile {
			r.checkImageContents(file, workload)
		}
	}
}

func (r *run) addWorkload(file *sourceFile, workload iac.Workload) {
	holder := graph.Holder{
		Kind:            workload.Kind,
		Name:            workload.Name,
		Location:        graph.Location{Path: workload.Path, Line: workload.Line},
		Environment:     r.environmentFor(workload.Path, workload.Environment, workload.Namespace),
		Untrusted:       workload.Untrusted,
		UntrustedReason: workload.UntrustedReason,
		UntrustedProven: workload.UntrustedProven,
	}
	if workload.Telemetry.Name != "" {
		holder.Sinks = append(holder.Sinks, graph.Sink{
			Kind:     graph.SinkTelemetry,
			Detail:   workload.Telemetry.Name,
			Location: graph.Location{Path: workload.Path, Line: workload.Telemetry.Line},
		})
	}
	for _, dump := range workload.EnvDumps {
		holder.Sinks = append(holder.Sinks, graph.Sink{
			Kind:     graph.SinkEnvDump,
			Detail:   dump.Command,
			Location: graph.Location{Path: workload.Path, Line: dump.Line},
		})
	}
	holderID := r.graph.AddHolder(holder)

	directory := directoryOf(file.path)
	for _, variable := range workload.Env {
		r.bind(holderID, file.path, variable, directory, workload.Kind == graph.HolderComposeService)
	}
	for _, envFile := range workload.EnvFiles {
		for _, entry := range r.dotenvEntries(directory, envFile.Path) {
			variable := entry.EnvVar(graph.DeliveryEnvFile)
			variable.Line = envFile.Line
			r.bind(holderID, file.path, variable, directory, false)
		}
	}
}

func (r *run) dotenvEntries(directory, name string) []iac.DotenvEntry {
	target, ok := r.byPath[joinPath(directory, name)]
	if !ok || target.kind != kindDotenv {
		return nil
	}
	return iac.ParseDotenv(target.data)
}

func (r *run) bind(holderID, filePath string, variable iac.EnvVar, directory string, interpolates bool) {
	edge := graph.Edge{
		Holder:   holderID,
		Delivery: variable.Delivery,
		Plain:    variable.Plain,
		Location: graph.Location{Path: filePath, Line: variable.Line},
	}
	secrets := r.scanner.secrets
	switch variable.Kind {
	case iac.ValueLiteral:
		if matches := secrets.Detect(variable.Name + "=" + variable.Value); len(matches) > 0 {
			for _, match := range matches {
				r.bindLiteral(edge, match, false)
			}
			return
		}
		if provider, ok := secrets.ProviderForEnvVar(variable.Name); ok {
			r.bindReference(edge, "env:"+variable.Name, provider, true)
		}
	case iac.ValueInterpolated, iac.ValueEmpty:
		name := cmp.Or(variable.Source, variable.Name)
		if interpolates {
			if entry, example, found := r.interpolationEntry(directory, name); found {
				if matches := secrets.Detect(name + "=" + entry.Value); len(matches) > 0 {
					for _, match := range matches {
						r.bindLiteral(edge, match, example)
					}
					return
				}
			}
		}
		provider, ok := secrets.ProviderForEnvVar(variable.Name)
		if !ok {
			provider, ok = secrets.ProviderForEnvVar(name)
		}
		if ok {
			r.bindReference(edge, "env:"+name, provider, false)
		}
	case iac.ValueSecretRef:
		if provider, ok := r.providerForSecret(variable); ok {
			r.bindReference(edge, variable.Source, provider, false)
		}
	}
}

func (r *run) interpolationEntry(directory, name string) (iac.DotenvEntry, bool, bool) {
	for _, candidate := range []struct {
		file    string
		example bool
	}{{".env", false}, {".env.example", true}, {".env.sample", true}, {".env.template", true}} {
		for _, entry := range r.dotenvEntries(directory, candidate.file) {
			if entry.Name == name {
				return entry, candidate.example, true
			}
		}
	}
	return iac.DotenvEntry{}, false, false
}

func (r *run) providerForSecret(variable iac.EnvVar) (string, bool) {
	secrets := r.scanner.secrets
	if provider, ok := secrets.ProviderForEnvVar(variable.Name); ok {
		return provider, true
	}
	if provider, ok := actionInputProviders[strings.ToLower(variable.Name)]; ok {
		return provider, true
	}
	_, secretName, _ := strings.Cut(variable.Source, ":")
	for _, name := range []string{secretName, variable.Name} {
		if provider, ok := secrets.ProviderForName(name); ok && !cloudProviders[provider] {
			return provider, true
		}
	}
	return "", false
}

func (r *run) bindLiteral(edge graph.Edge, match secret.Match, inferred bool) {
	key := literalKey(match.Fingerprint)
	r.graph.AddCredential(graph.Credential{Key: key, Kind: graph.KindLiteral, Provider: match.Provider, Reach: r.reachOf(match.Provider), Redacted: match.Redacted, Fingerprint: match.Fingerprint, Digests: match.Digests})
	edge.Credential = key
	edge.Inferred = inferred
	r.graph.AddEdge(edge)
}

func (r *run) bindReference(edge graph.Edge, identity, provider string, inferred bool) {
	key := referenceKey(identity)
	r.graph.AddCredential(graph.Credential{Key: key, Kind: graph.KindReference, Provider: provider, Reach: r.reachOf(provider), Name: identity})
	edge.Credential = key
	edge.Inferred = inferred
	r.graph.AddEdge(edge)
}

func (r *run) checkImageContents(file *sourceFile, workload iac.Workload) {
	secrets := r.scanner.secrets
	for _, variable := range workload.Env {
		if variable.Delivery != graph.DeliveryImageEnv && variable.Delivery != graph.DeliveryBuildArg {
			continue
		}
		instruction := "ENV"
		if variable.Delivery == graph.DeliveryBuildArg {
			instruction = "ARG"
		}
		if matches := secrets.Detect(variable.Name + "=" + variable.Value); len(matches) > 0 {
			r.emit(findingSpec{
				rule:       ruleCredentialInImage,
				title:      fmt.Sprintf("%s key %s set with %s in %s", r.providerName(matches[0].Provider), matches[0].Redacted, instruction, file.path),
				method:     finding.MethodPattern,
				confidence: finding.ConfidenceHigh,
				unproven:   []string{"Whether the key is still active."},
				evidence:   []finding.Evidence{r.evidenceAt(file.path, variable.Line)},
			})
			continue
		}
		provider, known := secrets.ProviderForEnvVar(variable.Name)
		if !known || (instruction == "ENV" && variable.Value == "") {
			continue
		}
		confidence := finding.ConfidenceHigh
		var flags []finding.Flag
		var unproven []string
		if instruction == "ARG" {
			confidence = finding.ConfidenceMedium
			flags = []finding.Flag{finding.FlagInferred}
			unproven = []string{"Whether the build passes a real value for this argument."}
		}
		r.emit(findingSpec{
			rule:       ruleCredentialInImage,
			title:      fmt.Sprintf("%s credential %s is set with %s in %s", r.providerName(provider), variable.Name, instruction, file.path),
			method:     finding.MethodPattern,
			confidence: confidence,
			flags:      flags,
			unproven:   unproven,
			evidence:   []finding.Evidence{r.evidenceAt(file.path, variable.Line)},
		})
	}
	r.checkEnvFileCopies(file, workload)
}

func (r *run) checkEnvFileCopies(file *sourceFile, workload iac.Workload) {
	directory := directoryOf(file.path)
	contextCopied := false
	for _, copied := range workload.Copies {
		source := strings.TrimPrefix(copied.Source, "./")
		switch {
		case isDotenvName(path.Base(source)) && !isExampleFile(source):
			r.emit(findingSpec{
				rule:       ruleCredentialInImage,
				title:      fmt.Sprintf("Dotenv file %s is copied into the image by %s", source, file.path),
				method:     finding.MethodPattern,
				confidence: finding.ConfidenceHigh,
				unproven:   []string{"Whether the file contains credentials at build time."},
				evidence:   []finding.Evidence{r.evidenceAt(file.path, copied.Line)},
			})
		case source == "." || source == "*":
			if !contextCopied && r.dotenvPresentAndNotIgnored(directory) {
				contextCopied = true
				r.emit(findingSpec{
					rule:       ruleCredentialInImage,
					title:      fmt.Sprintf("The build context copied by %s includes a dotenv file", file.path),
					method:     finding.MethodPattern,
					confidence: finding.ConfidenceMedium,
					flags:      []finding.Flag{finding.FlagInferred},
					unproven: []string{
						"The build context is assumed to be the Dockerfile directory.",
						"Whether the dotenv file exists in the environment that builds the image.",
					},
					evidence: []finding.Evidence{r.evidenceAt(file.path, copied.Line)},
				})
			}
		}
	}
}

func (r *run) dotenvPresentAndNotIgnored(directory string) bool {
	dotenv, ok := r.byPath[joinPath(directory, ".env")]
	if !ok || dotenv.kind != kindDotenv {
		return false
	}
	ignore, ok := r.byPath[joinPath(directory, ".dockerignore")]
	if !ok {
		return true
	}
	for _, line := range strings.Split(string(ignore.data), "\n") {
		pattern := strings.TrimPrefix(strings.TrimSpace(line), "**/")
		if pattern == "" || strings.HasPrefix(pattern, "#") || strings.HasPrefix(pattern, "!") {
			continue
		}
		if matched, err := path.Match(pattern, ".env"); err == nil && matched {
			return false
		}
	}
	return true
}

func isDotenvName(name string) bool {
	lower := strings.ToLower(name)
	return lower == ".env" || strings.HasPrefix(lower, ".env.") || strings.HasSuffix(lower, ".env")
}
