package source

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"
)

type Kind string

const (
	KindOther         Kind = "other"
	KindEnable        Kind = "enable"
	KindInvoke        Kind = "invoke"
	KindList          Kind = "list"
	KindLoggingRead   Kind = "logging-read"
	KindLoggingDelete Kind = "logging-delete"
	KindLoggingWrite  Kind = "logging-write"
	KindKeyCreate     Kind = "key-create"
)

const (
	TypeCloudTrail = "cloudtrail"
	TypeGCP        = "gcp"
	TypeAzure      = "azure"
	TypeUsage      = "usage"
)

var Types = []string{TypeCloudTrail, TypeGCP, TypeAzure, TypeUsage}

type Event struct {
	ID        string
	Time      time.Time
	Source    string
	File      string
	Principal string
	Account   string
	Region    string
	Action    string
	Service   string
	Model     string
	SourceIP  string
	UserAgent string
	KeyID     string
	Kind      Kind
	Streaming bool
	Failed    bool
	Count     int
	Cost      float64
}

func (e Event) Requests() int {
	if e.Count > 0 {
		return e.Count
	}
	return 1
}

func (e Event) Summary() string {
	summary := fmt.Sprintf("%s by %s", e.Action, e.Principal)
	if e.Model != "" {
		summary += " on " + e.Model
	}
	if e.SourceIP != "" {
		summary += " from " + e.SourceIP
	}
	return summary
}

func SortEvents(events []Event) {
	sort.SliceStable(events, func(i, j int) bool { return events[i].Time.Before(events[j].Time) })
}

func readMaybeGzip(data []byte) ([]byte, error) {
	if len(data) < 2 || data[0] != 0x1f || data[1] != 0x8b {
		return data, nil
	}
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("open gzip stream: %w", err)
	}
	defer func() { _ = reader.Close() }()
	decompressed, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("decompress: %w", err)
	}
	return decompressed, nil
}

func jsonRecords(data []byte, containers ...string) ([]json.RawMessage, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, errors.New("the file is empty")
	}
	if trimmed[0] == '[' {
		var records []json.RawMessage
		if err := json.Unmarshal(trimmed, &records); err != nil {
			return nil, fmt.Errorf("decode json array: %w", err)
		}
		return records, nil
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &object); err == nil {
		for _, name := range containers {
			if raw, ok := object[name]; ok {
				var records []json.RawMessage
				if err := json.Unmarshal(raw, &records); err != nil {
					return nil, fmt.Errorf("decode %s: %w", name, err)
				}
				return records, nil
			}
		}
		return []json.RawMessage{json.RawMessage(trimmed)}, nil
	}
	var records []json.RawMessage
	for _, line := range bytes.Split(trimmed, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var record json.RawMessage
		if err := json.Unmarshal(line, &record); err != nil {
			return nil, fmt.Errorf("decode json lines: %w", err)
		}
		records = append(records, record)
	}
	return records, nil
}

func parseTime(value string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05", "2006-01-02 15:04:05", "2006-01-02"} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognised time %q", value)
}

type Result struct {
	Events  []Event
	Skipped int
}

func Load(sourceType, fileName string, data []byte, options UsageOptions) (Result, error) {
	decompressed, err := readMaybeGzip(data)
	if err != nil {
		return Result{}, fmt.Errorf("%s: %w", fileName, err)
	}
	var result Result
	switch sourceType {
	case TypeCloudTrail:
		result, err = parseCloudTrail(fileName, decompressed)
	case TypeGCP:
		result, err = parseGCP(fileName, decompressed)
	case TypeAzure:
		result, err = parseAzure(fileName, decompressed)
	case TypeUsage:
		result, err = parseUsage(fileName, decompressed, options)
	default:
		return Result{}, fmt.Errorf("unknown source type %q: want %v", sourceType, Types)
	}
	if err != nil {
		return Result{}, fmt.Errorf("%s: %w", fileName, err)
	}
	return result, nil
}
