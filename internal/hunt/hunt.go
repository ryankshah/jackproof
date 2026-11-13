package hunt

import (
	"fmt"
	"sort"
	"time"

	"github.com/ryankshah/jackproof/internal/config"
	"github.com/ryankshah/jackproof/internal/finding"
	"github.com/ryankshah/jackproof/internal/hunt/source"
	"github.com/ryankshah/jackproof/internal/rules"
)

const (
	ruleEnableInvoke = "JP-HUNT-001"
	ruleVolume       = "JP-HUNT-002"
	ruleNewModel     = "JP-HUNT-003"
	ruleNetwork      = "JP-HUNT-004"
	ruleKeyUse       = "JP-HUNT-005"
	ruleRecon        = "JP-HUNT-006"
	ruleUnmapped     = "JP-HUNT-007"
	ruleStreaming    = "JP-HUNT-008"

	maxEvidence = 8
)

var requiredRules = []string{ruleEnableInvoke, ruleVolume, ruleNewModel, ruleNetwork, ruleKeyUse, ruleRecon, ruleUnmapped, ruleStreaming}

type CodeMap struct {
	Loaded    bool
	Providers map[string]bool
}

type Options struct {
	Config   *config.Config
	Rules    *rules.Catalogue
	Networks *Networks
	Code     CodeMap
}

type hunter struct {
	settings config.Hunt
	options  Options
	events   []source.Event
	findings []finding.Finding
	seen     map[string]bool
}

func Analyze(events []source.Event, options Options) ([]finding.Finding, error) {
	for _, id := range requiredRules {
		if _, ok := options.Rules.Get(id); !ok {
			return nil, fmt.Errorf("rule catalogue is missing %s", id)
		}
	}
	sorted := append([]source.Event(nil), events...)
	source.SortEvents(sorted)
	h := &hunter{settings: options.Config.HuntSettings(), options: options, events: sorted, seen: make(map[string]bool)}
	h.enableThenInvoke()
	h.volume()
	h.newModels()
	h.networks()
	h.keyUse()
	h.reconnaissance()
	h.unmapped()
	h.streaming()
	finding.Sort(h.findings)
	return h.findings, nil
}

type alert struct {
	rule       string
	confidence finding.Confidence
	severity   finding.Severity
	flags      []finding.Flag
	unproven   []string
	title      string
	events     []source.Event
}

func (h *hunter) emit(a alert) {
	rule, _ := h.options.Rules.Get(a.rule)
	evidence := make([]finding.Evidence, 0, maxEvidence)
	for _, event := range a.events {
		if len(evidence) == maxEvidence {
			break
		}
		evidence = append(evidence, finding.Evidence{Record: event.ID, Timestamp: event.Time, Excerpt: event.Summary()})
	}
	if len(evidence) == 0 {
		return
	}
	f := rule.NewFinding(finding.MethodLogCorrelation, a.confidence, evidence...)
	f.Title = a.title
	if a.severity != "" {
		f.Severity = a.severity
	}
	f.Flags = append(f.Flags, a.flags...)
	f.Unproven = a.unproven
	if h.seen[f.ID+"|"+a.title] {
		return
	}
	h.seen[f.ID+"|"+a.title] = true
	h.findings = append(h.findings, f)
}

func (h *hunter) byPrincipal(match func(source.Event) bool) (map[string][]source.Event, []string) {
	groups := make(map[string][]source.Event)
	for _, event := range h.events {
		if event.Principal != "" && match(event) {
			groups[event.Principal] = append(groups[event.Principal], event)
		}
	}
	principals := make([]string, 0, len(groups))
	for principal := range groups {
		principals = append(principals, principal)
	}
	sort.Strings(principals)
	return groups, principals
}

func isInvoke(event source.Event) bool {
	return event.Kind == source.KindInvoke && !event.Failed
}

func (h *hunter) enableThenInvoke() {
	for _, enable := range h.events {
		if enable.Kind != source.KindEnable || enable.Failed || enable.Principal == "" {
			continue
		}
		for _, invoke := range h.events {
			if invoke.Time.Before(enable.Time) || invoke.Time.Sub(enable.Time) > h.settings.EnableThenInvokeWindow {
				continue
			}
			if !isInvoke(invoke) || invoke.Principal != enable.Principal || invoke.Source != enable.Source {
				continue
			}
			h.emit(alert{
				rule:       ruleEnableInvoke,
				confidence: finding.ConfidenceHigh,
				title: fmt.Sprintf("%s enabled model access and invoked a model %s later", enable.Principal,
					invoke.Time.Sub(enable.Time).Round(time.Second)),
				events: []source.Event{enable, invoke},
			})
			break
		}
	}
}

func median(values []float64) float64 {
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	middle := len(sorted) / 2
	if len(sorted)%2 == 1 {
		return sorted[middle]
	}
	return (sorted[middle-1] + sorted[middle]) / 2
}

type bucket struct {
	start    time.Time
	requests float64
	cost     float64
	events   []source.Event
}

func (h *hunter) volume() {
	groups, principals := h.byPrincipal(isInvoke)
	for _, principal := range principals {
		buckets := make(map[int64]*bucket)
		var order []int64
		for _, event := range groups[principal] {
			start := event.Time.Truncate(h.settings.VolumePeriod)
			key := start.Unix()
			current, ok := buckets[key]
			if !ok {
				current = &bucket{start: start}
				buckets[key] = current
				order = append(order, key)
			}
			current.requests += float64(event.Requests())
			current.cost += event.Cost
			current.events = append(current.events, event)
		}
		sort.Slice(order, func(i, j int) bool { return order[i] < order[j] })
		for position, key := range order {
			h.checkBucket(principal, buckets, order, position, key)
		}
	}
}

func (h *hunter) checkBucket(principal string, buckets map[int64]*bucket, order []int64, position int, key int64) {
	first := max(0, position-h.settings.BaselinePeriods)
	var requests, costs []float64
	for _, previous := range order[first:position] {
		requests = append(requests, buckets[previous].requests)
		if buckets[previous].cost > 0 {
			costs = append(costs, buckets[previous].cost)
		}
	}
	current := buckets[key]
	period := h.settings.VolumePeriod
	if len(requests) >= h.settings.BaselineMinPeriods {
		baseline := median(requests)
		if current.requests >= float64(h.settings.MinRequests) && current.requests > h.settings.VolumeMultiplier*baseline {
			h.emit(alert{
				rule:       ruleVolume,
				confidence: finding.ConfidenceMedium,
				flags:      []finding.Flag{finding.FlagInferred},
				unproven:   []string{"Whether the increase reflects a planned change in the workload."},
				title: fmt.Sprintf("%s made %.0f requests in the %s starting %s, %.1f times its baseline median of %.0f per %s over %d earlier periods",
					principal, current.requests, period, current.start.Format("2006-01-02 15:04Z"), current.requests/max(baseline, 1), baseline, period, len(requests)),
				events: current.events,
			})
		}
	}
	if len(costs) >= h.settings.BaselineMinPeriods && current.cost > 0 {
		baseline := median(costs)
		if current.cost > h.settings.VolumeMultiplier*baseline {
			h.emit(alert{
				rule:       ruleVolume,
				confidence: finding.ConfidenceMedium,
				flags:      []finding.Flag{finding.FlagInferred},
				unproven:   []string{"Whether the increase reflects a planned change in the workload."},
				title: fmt.Sprintf("%s spent %.2f in the %s starting %s, %.1f times its baseline median of %.2f per %s over %d earlier periods",
					principal, current.cost, period, current.start.Format("2006-01-02 15:04Z"), current.cost/max(baseline, 0.01), baseline, period, len(costs)),
				events: current.events,
			})
		}
	}
}
