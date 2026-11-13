package lang

import (
	"regexp"
	"sort"
	"strings"
)

type syntax struct {
	comment  string
	envReads []*regexp.Regexp
	assign   *regexp.Regexp
	sinks    []*regexp.Regexp
}

func pythonSyntax() syntax {
	return syntax{
		comment: "#",
		envReads: []*regexp.Regexp{
			regexp.MustCompile(`(?:os\.)?environ\[\s*["']([A-Za-z0-9_]+)["']\s*\]`),
			regexp.MustCompile(`(?:os\.)?environ\.get\(\s*["']([A-Za-z0-9_]+)["']`),
			regexp.MustCompile(`(?:os\.)?getenv\(\s*["']([A-Za-z0-9_]+)["']`),
		},
		assign: regexp.MustCompile(`^\s*([A-Za-z_]\w*)\s*(?::[^=]+)?=\s*(.*)$`),
		sinks: []*regexp.Regexp{
			regexp.MustCompile(`\b(?:print|pprint)\s*\(`),
			regexp.MustCompile(`\b(?:logging|logger|log|LOGGER|_logger)\.(?:debug|info|warning|warn|error|exception|critical|log)\s*\(`),
			regexp.MustCompile(`\braise\s+\w+(?:\.\w+)*\s*\(`),
			regexp.MustCompile(`\b(?:jsonify|JSONResponse|HTMLResponse|PlainTextResponse|HttpResponse|Response)\s*\(`),
			regexp.MustCompile(`\bwarnings\.warn\s*\(`),
		},
	}
}

func javascriptSyntax() syntax {
	return syntax{
		comment: "//",
		envReads: []*regexp.Regexp{
			regexp.MustCompile(`process\.env\.([A-Za-z_][A-Za-z0-9_]*)`),
			regexp.MustCompile(`process\.env\[\s*["'\x60]([A-Za-z0-9_]+)["'\x60]\s*\]`),
			regexp.MustCompile(`import\.meta\.env\.([A-Za-z_][A-Za-z0-9_]*)`),
			regexp.MustCompile(`Deno\.env\.get\(\s*["']([A-Za-z0-9_]+)["']`),
		},
		assign: regexp.MustCompile(`^\s*(?:export\s+)?(?:const|let|var)?\s*([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*(.*)$`),
		sinks: []*regexp.Regexp{
			regexp.MustCompile(`\bconsole\.(?:log|error|warn|info|debug|trace)\s*\(`),
			regexp.MustCompile(`\b(?:logger|log)\.(?:debug|info|warn|warning|error|log|trace|fatal)\s*\(`),
			regexp.MustCompile(`\bthrow\s+new\s+\w*Error\s*\(`),
			regexp.MustCompile(`\bres(?:ponse)?\.(?:send|json|write|end)\s*\(`),
			regexp.MustCompile(`\bNextResponse\.json\s*\(`),
			regexp.MustCompile(`\bnew\s+Response\s*\(`),
		},
	}
}

func (e *Extractor) extractLines(data []byte, syn syntax, clients []clientRule) Facts {
	var facts Facts
	tainted := make(map[string]string)
	wordPatterns := make(map[string]*regexp.Regexp)

	for index, line := range strings.Split(string(data), "\n") {
		lineNumber := index + 1
		if strings.HasPrefix(strings.TrimSpace(line), syn.comment) {
			continue
		}
		reads := e.credentialReads(syn, line)
		for _, name := range reads {
			facts.EnvReads = append(facts.EnvReads, EnvRead{Name: name, Line: lineNumber})
		}
		for _, rule := range clients {
			if matched := rule.compiled.FindString(line); matched != "" {
				facts.Clients = append(facts.Clients, Client{
					Provider:    rule.Provider,
					Constructor: strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(matched), "(")),
					Line:        lineNumber,
				})
			}
		}
		if sink, found := firstMatch(syn.sinks, line); found {
			for _, name := range reads {
				facts.Leaks = append(facts.Leaks, Leak{Env: name, Sink: sink, Line: lineNumber})
			}
			for variable, env := range tainted {
				pattern, ok := wordPatterns[variable]
				if !ok {
					pattern = regexp.MustCompile(`(?:^|[^\w$])` + regexp.QuoteMeta(variable) + `(?:[^\w$]|$)`)
					wordPatterns[variable] = pattern
				}
				if pattern.MatchString(line) {
					facts.Leaks = append(facts.Leaks, Leak{Env: env, Variable: variable, Sink: sink, Line: lineNumber})
				}
			}
		}
		if match := syn.assign.FindStringSubmatch(line); match != nil {
			for _, name := range e.credentialReads(syn, match[2]) {
				tainted[match[1]] = name
			}
		}
	}
	sort.SliceStable(facts.Leaks, func(i, j int) bool {
		if facts.Leaks[i].Line != facts.Leaks[j].Line {
			return facts.Leaks[i].Line < facts.Leaks[j].Line
		}
		return facts.Leaks[i].Variable < facts.Leaks[j].Variable
	})
	return facts
}

func (e *Extractor) credentialReads(syn syntax, text string) []string {
	var names []string
	for _, pattern := range syn.envReads {
		for _, match := range pattern.FindAllStringSubmatch(text, -1) {
			if e.isCredentialEnv(match[1]) {
				names = append(names, match[1])
			}
		}
	}
	return names
}

func firstMatch(patterns []*regexp.Regexp, text string) (string, bool) {
	for _, pattern := range patterns {
		if matched := pattern.FindString(text); matched != "" {
			return strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(matched), "(")), true
		}
	}
	return "", false
}
