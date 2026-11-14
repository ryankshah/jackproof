package main

import (
	"github.com/ryankshah/jackproof/internal/finding"
	"github.com/ryankshah/jackproof/internal/graph"
	"github.com/ryankshah/jackproof/internal/scan"
)

type analysis struct {
	findings []finding.Finding
	coverage finding.Coverage
	graph    *graph.Graph
	scan     *scan.Result
}

func analyzeAll(kit toolkit, paths []string) (analysis, error) {
	result, err := runScanner(kit, paths)
	if err != nil {
		return analysis{}, err
	}
	postureFindings, postureCoverage, err := posturePass(kit, result)
	if err != nil {
		return analysis{}, err
	}
	postureCoverage.FilesScanned = nil
	coverage := result.Coverage
	coverage.Merge(postureCoverage)

	findings := append(append([]finding.Finding(nil), result.Findings...), postureFindings...)
	finding.Sort(findings)
	return analysis{findings: findings, coverage: coverage, graph: result.Graph, scan: result}, nil
}
