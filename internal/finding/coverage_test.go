package finding

import (
	"reflect"
	"testing"
)

func TestCoverageMerge(t *testing.T) {
	a := Coverage{FilesScanned: map[string]int{"go": 2, "yaml": 1}, UnverifiedRules: []string{"JP-KEY-001"}}
	a.AddSkipped("big.bin", "binary file")
	b := Coverage{FilesScanned: map[string]int{"go": 1, "python": 4}, UnverifiedRules: []string{"JP-KEY-001", "JP-POS-002"}}
	b.AddSkipped("huge.log", "larger than limit")

	var merged Coverage
	merged.Merge(a)
	merged.Merge(b)

	if want := map[string]int{"go": 3, "yaml": 1, "python": 4}; !reflect.DeepEqual(merged.FilesScanned, want) {
		t.Errorf("FilesScanned = %v, want %v", merged.FilesScanned, want)
	}
	if len(merged.FilesSkipped) != 2 {
		t.Errorf("FilesSkipped = %v, want 2 entries", merged.FilesSkipped)
	}
	if want := []string{"JP-KEY-001", "JP-POS-002"}; !reflect.DeepEqual(merged.UnverifiedRules, want) {
		t.Errorf("UnverifiedRules = %v, want %v", merged.UnverifiedRules, want)
	}
	if merged.TotalScanned() != 8 {
		t.Errorf("TotalScanned = %d, want 8", merged.TotalScanned())
	}
	if want := []string{"go", "python", "yaml"}; !reflect.DeepEqual(merged.Kinds(), want) {
		t.Errorf("Kinds = %v, want %v", merged.Kinds(), want)
	}
}

func TestCoverageAddScanned(t *testing.T) {
	var c Coverage
	for _, kind := range []string{"go", "go", "dockerfile"} {
		c.AddScanned(kind)
	}
	if c.FilesScanned["go"] != 2 || c.FilesScanned["dockerfile"] != 1 {
		t.Errorf("FilesScanned = %v", c.FilesScanned)
	}
}
