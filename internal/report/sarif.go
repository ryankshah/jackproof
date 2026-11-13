package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/ryankshah/jackproof/internal/finding"
)

const (
	sarifVersion = "2.1.0"
	sarifSchema  = "https://json.schemastore.org/sarif-2.1.0.json"
	sourceRoot   = "%SRCROOT%"
)

var securitySeverity = map[finding.Severity]string{
	finding.SeverityCritical: "9.5",
	finding.SeverityHigh:     "8.0",
	finding.SeverityMedium:   "5.5",
	finding.SeverityLow:      "3.0",
	finding.SeverityInfo:     "1.0",
}

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name    string      `json:"name"`
	Version string      `json:"version,omitempty"`
	Rules   []sarifRule `json:"rules"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifRule struct {
	ID                   string         `json:"id"`
	ShortDescription     sarifText      `json:"shortDescription"`
	FullDescription      *sarifText     `json:"fullDescription,omitempty"`
	Help                 sarifText      `json:"help"`
	HelpURI              string         `json:"helpUri,omitempty"`
	DefaultConfiguration sarifConfig    `json:"defaultConfiguration"`
	Properties           map[string]any `json:"properties"`
}

type sarifConfig struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations,omitempty"`
	RelatedLocations    []sarifLocation   `json:"relatedLocations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Properties          map[string]any    `json:"properties"`
}

type sarifLocation struct {
	ID               int                   `json:"id,omitempty"`
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region"`
}

type sarifArtifact struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId"`
}

type sarifRegion struct {
	StartLine int        `json:"startLine"`
	EndLine   int        `json:"endLine"`
	Snippet   *sarifText `json:"snippet,omitempty"`
}

func sarifLevel(severity finding.Severity) string {
	switch severity {
	case finding.SeverityCritical, finding.SeverityHigh:
		return "error"
	case finding.SeverityMedium:
		return "warning"
	}
	return "note"
}

func WriteSARIF(w io.Writer, r Report) error {
	results := make([]sarifResult, 0, len(r.Findings))
	ruleSeen := make(map[string]finding.Finding)
	for _, f := range r.Findings {
		results = append(results, sarifResultFor(f))
		if _, ok := ruleSeen[f.Rule]; !ok {
			ruleSeen[f.Rule] = f
		}
	}
	ruleIDs := make([]string, 0, len(ruleSeen))
	for id := range ruleSeen {
		ruleIDs = append(ruleIDs, id)
	}
	sort.Strings(ruleIDs)
	sarifRules := make([]sarifRule, 0, len(ruleIDs))
	for _, id := range ruleIDs {
		sarifRules = append(sarifRules, r.sarifRuleFor(ruleSeen[id]))
	}

	document := sarifLog{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []sarifRun{{
			Tool:    sarifTool{Driver: sarifDriver{Name: toolName, Version: r.Version, Rules: sarifRules}},
			Results: results,
		}},
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(document); err != nil {
		return fmt.Errorf("write sarif report: %w", err)
	}
	return nil
}

func (r Report) sarifRuleFor(sample finding.Finding) sarifRule {
	rule := sarifRule{
		ID:                   sample.Rule,
		ShortDescription:     sarifText{Text: sample.Title},
		Help:                 sarifText{Text: sample.Remediation},
		DefaultConfiguration: sarifConfig{Level: sarifLevel(sample.Severity)},
		Properties: map[string]any{
			"security-severity": securitySeverity[sample.Severity],
			"tags":              []string{"security", "llmjacking"},
		},
	}
	if len(sample.Refs) > 0 {
		rule.HelpURI = sample.Refs[0]
	}
	if r.Rules != nil {
		if definition, ok := r.Rules.Get(sample.Rule); ok {
			rule.ShortDescription = sarifText{Text: definition.Title}
			rule.FullDescription = &sarifText{Text: definition.Description}
			rule.Help = sarifText{Text: definition.Remediation}
			rule.DefaultConfiguration = sarifConfig{Level: sarifLevel(definition.Severity)}
			rule.Properties["security-severity"] = securitySeverity[definition.Severity]
			rule.Properties["verified"] = definition.Verified
		}
	}
	return rule
}

func sarifResultFor(f finding.Finding) sarifResult {
	message := f.Title
	if len(f.Unproven) > 0 {
		message += " Not established: " + strings.Join(f.Unproven, " ")
	}
	flags := make([]string, len(f.Flags))
	for i, flag := range f.Flags {
		flags[i] = string(flag)
	}
	result := sarifResult{
		RuleID:              f.Rule,
		Level:               sarifLevel(f.Severity),
		Message:             sarifText{Text: message},
		PartialFingerprints: map[string]string{"jackproofFindingId/v1": f.ID},
		Properties: map[string]any{
			"confidence": string(f.Confidence),
			"severity":   string(f.Severity),
			"method":     string(f.Method),
			"flags":      flags,
			"module":     string(f.Module),
		},
	}
	related := 0
	for _, evidence := range f.Evidence {
		if evidence.Path == "" {
			continue
		}
		entry := sarifLocation{PhysicalLocation: sarifPhysicalLocation{
			ArtifactLocation: sarifArtifact{URI: evidence.Path, URIBaseID: sourceRoot},
			Region:           sarifRegion{StartLine: evidence.StartLine, EndLine: evidence.EndLine},
		}}
		if evidence.Excerpt != "" {
			entry.PhysicalLocation.Region.Snippet = &sarifText{Text: evidence.Excerpt}
		}
		if len(result.Locations) == 0 {
			result.Locations = append(result.Locations, entry)
			continue
		}
		related++
		entry.ID = related
		result.RelatedLocations = append(result.RelatedLocations, entry)
	}
	return result
}
