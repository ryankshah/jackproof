package diff

import (
	"sort"
	"strings"

	"github.com/ryankshah/jackproof/internal/finding"
)

type Change struct {
	Before finding.Finding
	After  finding.Finding
}

type Result struct {
	Added     []finding.Finding
	Removed   []finding.Finding
	Changed   []Change
	Unchanged int
}

func key(f finding.Finding) string {
	location := ""
	if len(f.Evidence) > 0 {
		location = f.Evidence[0].Path
		if location == "" {
			location = f.Evidence[0].Record
		}
	}
	return strings.Join([]string{f.Rule, location, f.Title}, "\x00")
}

func Compare(base, head []finding.Finding) Result {
	baseByKey := make(map[string][]finding.Finding)
	for _, f := range base {
		baseByKey[key(f)] = append(baseByKey[key(f)], f)
	}
	var result Result
	for _, f := range head {
		candidates := baseByKey[key(f)]
		if len(candidates) == 0 {
			result.Added = append(result.Added, f)
			continue
		}
		previous := candidates[0]
		baseByKey[key(f)] = candidates[1:]
		if previous.Severity != f.Severity || previous.Confidence != f.Confidence {
			result.Changed = append(result.Changed, Change{Before: previous, After: f})
			continue
		}
		result.Unchanged++
	}
	for _, remaining := range baseByKey {
		result.Removed = append(result.Removed, remaining...)
	}
	finding.Sort(result.Added)
	finding.Sort(result.Removed)
	sort.SliceStable(result.Changed, func(i, j int) bool { return result.Changed[i].After.ID < result.Changed[j].After.ID })
	return result
}
