package iac

import (
	"bufio"
	"bytes"
	"regexp"
	"strings"

	"github.com/ryankshah/jackproof/internal/graph"
)

var dotenvName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

type DotenvEntry struct {
	Name  string
	Value string
	Line  int
}

func ParseDotenv(data []byte) []DotenvEntry {
	var entries []DotenvEntry
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		name, value, found := strings.Cut(line, "=")
		name = strings.TrimSpace(name)
		if !found || !dotenvName.MatchString(name) {
			continue
		}
		entries = append(entries, DotenvEntry{Name: name, Value: unquote(strings.TrimSpace(value)), Line: lineNumber})
	}
	return entries
}

func (e DotenvEntry) EnvVar(delivery graph.Delivery) EnvVar {
	kind, source := ClassifyValue(e.Value)
	return EnvVar{Name: e.Name, Value: e.Value, Kind: kind, Source: source, Delivery: delivery, Plain: true, Line: e.Line}
}

func unquote(value string) string {
	if len(value) >= 2 {
		first, last := value[0], value[len(value)-1]
		if (first == '"' || first == '\'') && first == last {
			return value[1 : len(value)-1]
		}
	}
	if index := strings.Index(value, " #"); index >= 0 {
		return strings.TrimSpace(value[:index])
	}
	return value
}
