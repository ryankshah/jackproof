package finding

import (
	"sort"
	"time"
)

type Skip struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

type TimeRange struct {
	Source string    `json:"source"`
	From   time.Time `json:"from"`
	To     time.Time `json:"to"`
}

type Coverage struct {
	FilesScanned    map[string]int `json:"files_scanned,omitempty"`
	FilesSkipped    []Skip         `json:"files_skipped,omitempty"`
	SkippedMore     int            `json:"files_skipped_more,omitempty"`
	LogSources      []string       `json:"log_sources,omitempty"`
	TimeRanges      []TimeRange    `json:"time_ranges,omitempty"`
	UnverifiedRules []string       `json:"unverified_rules,omitempty"`
}

func (c *Coverage) AddScanned(kind string) {
	if c.FilesScanned == nil {
		c.FilesScanned = make(map[string]int)
	}
	c.FilesScanned[kind]++
}

const MaxSkippedListed = 1000

func (c *Coverage) AddSkipped(path, reason string) {
	if len(c.FilesSkipped) >= MaxSkippedListed {
		c.SkippedMore++
		return
	}
	c.FilesSkipped = append(c.FilesSkipped, Skip{Path: path, Reason: reason})
}

func (c Coverage) TotalSkipped() int {
	return len(c.FilesSkipped) + c.SkippedMore
}

func (c *Coverage) Merge(other Coverage) {
	for kind, count := range other.FilesScanned {
		if c.FilesScanned == nil {
			c.FilesScanned = make(map[string]int)
		}
		c.FilesScanned[kind] += count
	}
	for _, skip := range other.FilesSkipped {
		c.AddSkipped(skip.Path, skip.Reason)
	}
	c.SkippedMore += other.SkippedMore
	c.LogSources = append(c.LogSources, other.LogSources...)
	c.TimeRanges = append(c.TimeRanges, other.TimeRanges...)
	c.UnverifiedRules = mergeSorted(c.UnverifiedRules, other.UnverifiedRules)
}

func (c Coverage) TotalScanned() int {
	total := 0
	for _, count := range c.FilesScanned {
		total += count
	}
	return total
}

func (c Coverage) Kinds() []string {
	kinds := make([]string, 0, len(c.FilesScanned))
	for kind := range c.FilesScanned {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	return kinds
}

func mergeSorted(a, b []string) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	for _, value := range a {
		seen[value] = struct{}{}
	}
	for _, value := range b {
		seen[value] = struct{}{}
	}
	merged := make([]string, 0, len(seen))
	for value := range seen {
		merged = append(merged, value)
	}
	sort.Strings(merged)
	return merged
}
