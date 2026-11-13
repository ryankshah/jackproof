package main

import (
	"encoding/json"
	"testing"

	"github.com/ryankshah/jackproof/internal/finding"
	"github.com/ryankshah/jackproof/internal/secret"
)

func secretFingerprint(key string) string {
	return secret.FullFingerprint(key)
}

func readTestFindings(t *testing.T, text string) []finding.Finding {
	t.Helper()
	var document struct {
		Findings []finding.Finding `json:"findings"`
	}
	if err := json.Unmarshal([]byte(text), &document); err != nil {
		t.Fatal(err)
	}
	return document.Findings
}
