package report

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/ryankshah/jackproof/internal/finding"
	"github.com/ryankshah/jackproof/internal/graph"
)

const jsonSchemaVersion = 1

type jsonDocument struct {
	Schema   int               `json:"schema"`
	Tool     string            `json:"tool"`
	Version  string            `json:"version"`
	Title    string            `json:"title"`
	Findings []finding.Finding `json:"findings"`
	Graph    *jsonGraph        `json:"graph,omitempty"`
	Coverage finding.Coverage  `json:"coverage"`
}

type jsonGraph struct {
	Credentials []graph.Credential `json:"credentials"`
	Holders     []graph.Holder     `json:"holders"`
	Edges       []graph.Edge       `json:"edges"`
}

func WriteJSON(w io.Writer, r Report) error {
	document := jsonDocument{
		Schema:   jsonSchemaVersion,
		Tool:     toolName,
		Version:  r.Version,
		Title:    r.Title,
		Findings: r.Findings,
		Coverage: r.Coverage,
	}
	if document.Findings == nil {
		document.Findings = []finding.Finding{}
	}
	if r.Graph != nil {
		document.Graph = &jsonGraph{
			Credentials: nonNil(r.Graph.Credentials()),
			Holders:     nonNil(r.Graph.Holders()),
			Edges:       nonNil(r.Graph.Edges()),
		}
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(document); err != nil {
		return fmt.Errorf("write json report: %w", err)
	}
	return nil
}

func nonNil[T any](values []T) []T {
	if values == nil {
		return []T{}
	}
	return values
}
