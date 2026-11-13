package iac

import (
	"path"
	"sort"
	"strings"

	"github.com/ryankshah/jackproof/internal/graph"
)

type dockerInstruction struct {
	keyword   string
	arguments string
	line      int
}

func ParseDockerfile(filePath string, data []byte) Workload {
	workload := Workload{
		Kind: graph.HolderDockerfile,
		Name: path.Base(filePath),
		Path: filePath,
		Line: 1,
	}
	for _, instruction := range dockerInstructions(string(data)) {
		switch instruction.keyword {
		case "ENV":
			for name, value := range dockerEnvPairs(instruction.arguments) {
				workload.Env = append(workload.Env, dockerVar(name, value, graph.DeliveryImageEnv, instruction.line))
			}
		case "ARG":
			name, value, _ := strings.Cut(strings.TrimSpace(instruction.arguments), "=")
			workload.Env = append(workload.Env, dockerVar(name, unquote(value), graph.DeliveryBuildArg, instruction.line))
		case "COPY", "ADD":
			for _, source := range dockerCopySources(instruction.arguments) {
				workload.Copies = append(workload.Copies, Copy{Source: source, Line: instruction.line})
			}
		}
	}
	sort.SliceStable(workload.Env, func(i, j int) bool {
		a, b := workload.Env[i], workload.Env[j]
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.Name < b.Name
	})
	return workload
}

func dockerVar(name, value string, delivery graph.Delivery, line int) EnvVar {
	kind, source := ClassifyValue(value)
	return EnvVar{Name: name, Value: value, Kind: kind, Source: source, Delivery: delivery, Line: line}
}

func dockerInstructions(text string) []dockerInstruction {
	var instructions []dockerInstruction
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	for index := 0; index < len(lines); index++ {
		trimmed := strings.TrimSpace(lines[index])
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		start := index + 1
		logical := trimmed
		for strings.HasSuffix(logical, `\`) && index+1 < len(lines) {
			index++
			next := strings.TrimSpace(lines[index])
			if strings.HasPrefix(next, "#") {
				continue
			}
			logical = strings.TrimSpace(strings.TrimSuffix(logical, `\`)) + " " + next
		}
		logical = strings.TrimSpace(strings.TrimSuffix(logical, `\`))
		keyword, arguments, _ := strings.Cut(logical, " ")
		instructions = append(instructions, dockerInstruction{keyword: strings.ToUpper(keyword), arguments: strings.TrimSpace(arguments), line: start})
	}
	return instructions
}

func dockerEnvPairs(arguments string) map[string]string {
	words := splitWords(arguments)
	pairs := make(map[string]string)
	if len(words) == 0 {
		return pairs
	}
	if !strings.Contains(words[0], "=") {
		pairs[words[0]] = strings.Join(words[1:], " ")
		return pairs
	}
	for _, word := range words {
		name, value, found := strings.Cut(word, "=")
		if found {
			pairs[name] = value
		}
	}
	return pairs
}

func dockerCopySources(arguments string) []string {
	var words []string
	for _, word := range splitWords(arguments) {
		if !strings.HasPrefix(word, "--") {
			words = append(words, word)
		}
	}
	if len(words) < 2 {
		return nil
	}
	return words[:len(words)-1]
}

func splitWords(text string) []string {
	var words []string
	var current strings.Builder
	var quote rune
	started := false
	for _, r := range text {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				current.WriteRune(r)
			}
		case r == '"' || r == '\'':
			quote = r
			started = true
		case r == ' ' || r == '\t':
			if started || current.Len() > 0 {
				words = append(words, current.String())
				current.Reset()
				started = false
			}
		default:
			current.WriteRune(r)
			started = true
		}
	}
	if started || current.Len() > 0 {
		words = append(words, current.String())
	}
	return words
}
