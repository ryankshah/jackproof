package source

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

const (
	ColumnTimestamp = "timestamp"
	ColumnPrincipal = "principal"
	ColumnModel     = "model"
	ColumnRequests  = "requests"
	ColumnCost      = "cost"
	ColumnSourceIP  = "source_ip"
)

var usageColumns = []string{ColumnTimestamp, ColumnPrincipal, ColumnModel, ColumnRequests, ColumnCost, ColumnSourceIP}

type UsageOptions struct {
	Columns map[string]string
}

func ParseColumns(spec string) (map[string]string, error) {
	columns := make(map[string]string)
	if strings.TrimSpace(spec) == "" {
		return columns, nil
	}
	for _, pair := range strings.Split(spec, ",") {
		field, header, found := strings.Cut(strings.TrimSpace(pair), "=")
		if !found || field == "" || header == "" {
			return nil, fmt.Errorf("column mapping %q must look like field=header", pair)
		}
		known := false
		for _, name := range usageColumns {
			if name == field {
				known = true
			}
		}
		if !known {
			return nil, fmt.Errorf("unknown usage field %q: want %s", field, strings.Join(usageColumns, ", "))
		}
		columns[field] = header
	}
	return columns, nil
}

func parseUsage(fileName string, data []byte, options UsageOptions) (Result, error) {
	reader := csv.NewReader(bytes.NewReader(data))
	reader.FieldsPerRecord = -1
	header, err := reader.Read()
	if err != nil {
		return Result{}, fmt.Errorf("read csv header: %w", err)
	}
	positions := make(map[string]int)
	for _, field := range usageColumns {
		name := field
		if mapped, ok := options.Columns[field]; ok {
			name = mapped
		}
		for index, column := range header {
			if strings.EqualFold(strings.TrimSpace(column), name) {
				positions[field] = index
			}
		}
	}
	for _, required := range []string{ColumnTimestamp, ColumnPrincipal} {
		if _, ok := positions[required]; !ok {
			return Result{}, fmt.Errorf("the csv has no column for %q: map one with --usage-columns", required)
		}
	}

	var result Result
	for row := 1; ; row++ {
		record, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			result.Skipped++
			continue
		}
		event, err := usageEvent(fileName, row, record, positions)
		if err != nil {
			result.Skipped++
			continue
		}
		result.Events = append(result.Events, event)
	}
	SortEvents(result.Events)
	return result, nil
}

func usageEvent(fileName string, row int, record []string, positions map[string]int) (Event, error) {
	field := func(name string) string {
		index, ok := positions[name]
		if !ok || index >= len(record) {
			return ""
		}
		return strings.TrimSpace(record[index])
	}
	when, err := usageTime(field(ColumnTimestamp))
	if err != nil {
		return Event{}, err
	}
	event := Event{
		ID: fmt.Sprintf("%s#%d", fileName, row), Time: when, Source: TypeUsage, File: fileName,
		Principal: field(ColumnPrincipal), Action: "usage", Service: "usage", Model: field(ColumnModel),
		SourceIP: field(ColumnSourceIP), Kind: KindInvoke, Count: 1,
	}
	if requests := field(ColumnRequests); requests != "" {
		count, err := strconv.ParseFloat(requests, 64)
		if err != nil {
			return Event{}, fmt.Errorf("requests: %w", err)
		}
		event.Count = int(count)
	}
	if cost := field(ColumnCost); cost != "" {
		event.Cost, err = strconv.ParseFloat(strings.TrimPrefix(cost, "$"), 64)
		if err != nil {
			return Event{}, fmt.Errorf("cost: %w", err)
		}
	}
	return event, nil
}

func usageTime(value string) (time.Time, error) {
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		return time.Unix(seconds, 0).UTC(), nil
	}
	return parseTime(value)
}
