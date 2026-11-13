package hunt

import (
	"bytes"
	"errors"
	"io"
	"regexp"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/ryankshah/jackproof/internal/config"
)

type sigmaDocument struct {
	Title       string `yaml:"title"`
	Name        string `yaml:"name"`
	ID          string `yaml:"id"`
	Status      string `yaml:"status"`
	Description string `yaml:"description"`
	Level       string `yaml:"level"`
	Detection   any    `yaml:"detection"`
	Logsource   any    `yaml:"logsource"`
	Correlation struct {
		Type      string         `yaml:"type"`
		Rules     []string       `yaml:"rules"`
		GroupBy   []string       `yaml:"group-by"`
		Timespan  string         `yaml:"timespan"`
		Condition map[string]any `yaml:"condition"`
	} `yaml:"correlation"`
}

func exportDocuments(t *testing.T, settings config.Hunt) []sigmaDocument {
	t.Helper()
	var out bytes.Buffer
	if err := ExportSigma(&out, settings); err != nil {
		t.Fatal(err)
	}
	var documents []sigmaDocument
	decoder := yaml.NewDecoder(&out)
	for {
		var document sigmaDocument
		err := decoder.Decode(&document)
		if errors.Is(err, io.EOF) {
			return documents
		}
		if err != nil {
			t.Fatalf("invalid yaml: %v", err)
		}
		documents = append(documents, document)
	}
}

func TestSigmaExportIsValidAndConsistent(t *testing.T) {
	documents := exportDocuments(t, config.DefaultHunt())
	if len(documents) < 15 {
		t.Fatalf("got %d documents", len(documents))
	}
	names := make(map[string]bool)
	ids := make(map[string]bool)
	uuid := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	for _, document := range documents {
		if document.Title == "" || document.Name == "" || document.Status != "experimental" || document.Description == "" || document.Level == "" {
			t.Errorf("document is incomplete: %+v", document)
		}
		if !uuid.MatchString(document.ID) {
			t.Errorf("%s has id %q", document.Name, document.ID)
		}
		if names[document.Name] || ids[document.ID] {
			t.Errorf("duplicate name or id for %s", document.Name)
		}
		names[document.Name], ids[document.ID] = true, true
		if (document.Detection == nil) == (document.Correlation.Type == "") {
			t.Errorf("%s must be either a detection or a correlation", document.Name)
		}
	}
	correlations := 0
	for _, document := range documents {
		if document.Correlation.Type == "" {
			continue
		}
		correlations++
		for _, referenced := range document.Correlation.Rules {
			if !names[referenced] {
				t.Errorf("%s references the unknown rule %s", document.Name, referenced)
			}
		}
		if document.Correlation.Timespan == "" || len(document.Correlation.GroupBy) == 0 {
			t.Errorf("%s has no timespan or group-by", document.Name)
		}
	}
	if correlations < 7 {
		t.Errorf("only %d correlations", correlations)
	}
}

func TestSigmaThresholdsComeFromConfiguration(t *testing.T) {
	settings := config.DefaultHunt()
	settings.DistinctIPs = 9
	settings.DistinctIPWindow = 20 * time.Minute
	settings.StreamConcurrency = 77
	settings.EnableThenInvokeWindow = 2 * time.Hour
	settings.MinRequests = 123
	var found = make(map[string]sigmaDocument)
	for _, document := range exportDocuments(t, settings) {
		found[document.Name] = document
	}
	addresses := found["jackproof_bedrock_many_source_addresses"]
	if addresses.Correlation.Condition["gte"] != 9 || addresses.Correlation.Condition["field"] != "sourceIPAddress" || addresses.Correlation.Timespan != "20m" {
		t.Errorf("addresses = %+v", addresses.Correlation)
	}
	if burst := found["jackproof_bedrock_streaming_burst"]; burst.Correlation.Condition["gte"] != 77 || burst.Correlation.Timespan != "1m" {
		t.Errorf("burst = %+v", burst.Correlation)
	}
	if enable := found["jackproof_bedrock_enable_then_invoke"]; enable.Correlation.Timespan != "2h" || enable.Correlation.Type != "temporal_ordered" {
		t.Errorf("enable = %+v", enable.Correlation)
	}
	if volume := found["jackproof_bedrock_volume"]; volume.Correlation.Condition["gte"] != 123 || !strings.Contains(volume.Description, "median") {
		t.Errorf("volume = %+v", volume)
	}
}

func TestSigmaDuration(t *testing.T) {
	tests := []struct {
		input time.Duration
		want  string
	}{
		{time.Minute, "1m"}, {10 * time.Minute, "10m"}, {time.Hour, "1h"}, {90 * time.Minute, "90m"},
		{24 * time.Hour, "1d"}, {30 * time.Second, "30s"}, {48 * time.Hour, "2d"},
	}
	for _, tt := range tests {
		if got := sigmaDuration(tt.input); got != tt.want {
			t.Errorf("sigmaDuration(%v) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestSigmaUUIDIsStable(t *testing.T) {
	first, again, other := sigmaUUID("a"), sigmaUUID("a"), sigmaUUID("b")
	if first != again || first == other {
		t.Error("uuids must be deterministic and distinct")
	}
}
