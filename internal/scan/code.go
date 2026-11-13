package scan

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/ryankshah/jackproof/internal/finding"
	"github.com/ryankshah/jackproof/internal/graph"
	"github.com/ryankshah/jackproof/internal/scan/lang"
)

const notebookUntrustedReason = "the notebook format"

func (r *run) processCode(file *sourceFile, hits []literalHit) {
	language := file.kind
	source := file.data
	lineMap := identityLine
	holderKind := graph.HolderCode
	if file.kind == kindNotebook {
		language = lang.Python
		holderKind = graph.HolderNotebook
		var err error
		source, lineMap, err = notebookSource(file.data)
		if err != nil {
			r.coverage.AddSkipped(file.path, fmt.Sprintf("structure not analysed: %v", err))
			source = nil
		}
	}

	var facts lang.Facts
	if len(source) > 0 {
		var err error
		facts, err = r.scanner.extractor.Extract(language, source)
		if err != nil {
			r.coverage.AddSkipped(file.path, fmt.Sprintf("structure not analysed: %v", err))
		}
	}
	if len(facts.EnvReads) == 0 && len(facts.Clients) == 0 && len(facts.Leaks) == 0 && len(hits) == 0 {
		return
	}

	holder := graph.Holder{
		Kind:        holderKind,
		Name:        file.path,
		Location:    graph.Location{Path: file.path, Line: 1},
		Environment: r.environmentFor(file.path, "", ""),
		Providers:   providersOf(facts.Clients),
	}
	if holderKind == graph.HolderNotebook {
		holder.Untrusted = true
		holder.UntrustedReason = notebookUntrustedReason
	}
	holderID := r.graph.AddHolder(holder)

	for _, read := range facts.EnvReads {
		provider, _ := r.scanner.secrets.ProviderForEnvVar(read.Name)
		r.bindReference(graph.Edge{
			Holder:   holderID,
			Delivery: graph.DeliveryCodeRead,
			Location: graph.Location{Path: file.path, Line: lineMap(read.Line)},
		}, "env:"+read.Name, provider, false)
	}
	for _, hit := range hits {
		r.bindLiteral(graph.Edge{
			Holder:   holderID,
			Delivery: graph.DeliveryCodeRead,
			Location: graph.Location{Path: file.path, Line: hit.line},
		}, hit.match.Provider, hit.match.Redacted, hit.match.Fingerprint, false)
	}
	for _, leak := range facts.Leaks {
		r.recordLeak(file, language, lineMap(leak.Line), leak)
	}
}

func identityLine(line int) int {
	return line
}

func providersOf(clients []lang.Client) []string {
	seen := make(map[string]struct{})
	for _, client := range clients {
		seen[client.Provider] = struct{}{}
	}
	providers := make([]string, 0, len(seen))
	for provider := range seen {
		providers = append(providers, provider)
	}
	sort.Strings(providers)
	return providers
}

func (r *run) recordLeak(file *sourceFile, language string, line int, leak lang.Leak) {
	confidence := finding.ConfidenceMedium
	flags := []finding.Flag{finding.FlagInferred}
	method := finding.MethodPattern
	if language == lang.Go {
		method = finding.MethodAST
		if leak.Strong {
			confidence = finding.ConfidenceHigh
			flags = nil
		}
	}
	subject := leak.Env
	if leak.Variable != "" {
		subject = fmt.Sprintf("%s (held in %s)", leak.Env, leak.Variable)
	}
	r.emit(findingSpec{
		rule:       ruleCredentialToSink,
		title:      fmt.Sprintf("%s reaches %s in %s", subject, leak.Sink, file.path),
		method:     method,
		confidence: confidence,
		flags:      flags,
		unproven:   []string{"Whether the value is masked before it reaches the call."},
		evidence:   []finding.Evidence{r.evidenceAt(file.path, line)},
	})
}

type notebookDocument struct {
	Cells []struct {
		CellType string          `json:"cell_type"`
		Source   json.RawMessage `json:"source"`
	} `json:"cells"`
}

func notebookSource(data []byte) ([]byte, func(int) int, error) {
	var document notebookDocument
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, nil, fmt.Errorf("decode notebook json: %w", err)
	}
	rawLines := strings.Split(string(data), "\n")
	var source strings.Builder
	var mapping []int
	cursor := 0
	for _, cell := range document.Cells {
		if cell.CellType != "code" {
			continue
		}
		for _, line := range cellLines(cell.Source) {
			found := locateLine(rawLines, cursor, line)
			if found >= 0 {
				cursor = found + 1
			}
			mapping = append(mapping, max(cursor, 1))
			source.WriteString(line)
			source.WriteByte('\n')
		}
	}
	lookup := func(line int) int {
		if line < 1 || line > len(mapping) {
			return 1
		}
		return mapping[line-1]
	}
	return []byte(source.String()), lookup, nil
}

func cellLines(raw json.RawMessage) []string {
	var asList []string
	if err := json.Unmarshal(raw, &asList); err == nil {
		lines := make([]string, len(asList))
		for i, line := range asList {
			lines[i] = strings.TrimSuffix(line, "\n")
		}
		return lines
	}
	var asText string
	if err := json.Unmarshal(raw, &asText); err == nil {
		return strings.Split(asText, "\n")
	}
	return nil
}

func locateLine(rawLines []string, from int, line string) int {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return -1
	}
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(trimmed); err != nil {
		return -1
	}
	inner := strings.TrimSpace(encoded.String())
	inner = inner[1 : len(inner)-1]
	for index := from; index < len(rawLines); index++ {
		if strings.Contains(rawLines[index], inner) {
			return index
		}
	}
	return -1
}
