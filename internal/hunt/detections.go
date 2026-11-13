package hunt

import (
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/ryankshah/jackproof/internal/finding"
	"github.com/ryankshah/jackproof/internal/hunt/source"
)

var serviceProviders = map[string][]string{
	"bedrock":      {"aws"},
	"vertex-ai":    {"gcp", "google-ai-studio"},
	"gemini-api":   {"google-ai-studio", "gcp"},
	"azure-openai": {"azure-openai"},
}

func (h *hunter) isHighCost(model string) bool {
	for _, pattern := range h.settings.HighCostModels {
		if matched, err := path.Match(strings.ToLower(pattern), strings.ToLower(model)); err == nil && matched {
			return true
		}
	}
	return false
}

func (h *hunter) newModels() {
	principalSeen := make(map[string]map[string]bool)
	accountSeen := make(map[string]map[string]bool)
	principalCount := make(map[string]int)
	for _, event := range h.events {
		if !isInvoke(event) || event.Model == "" || event.Principal == "" {
			continue
		}
		if principalSeen[event.Principal] == nil {
			principalSeen[event.Principal] = make(map[string]bool)
		}
		if accountSeen[event.Account] == nil {
			accountSeen[event.Account] = make(map[string]bool)
		}
		newForPrincipal := !principalSeen[event.Principal][event.Model]
		newForAccount := !accountSeen[event.Account][event.Model]
		established := principalCount[event.Principal] >= h.settings.MinHistory
		if newForPrincipal && established {
			severity := finding.SeverityLow
			scope := ""
			if newForAccount {
				severity = finding.SeverityMedium
				scope = ", and no other principal in the account had used it"
			}
			if h.isHighCost(event.Model) {
				severity = finding.SeverityHigh
			}
			h.emit(alert{
				rule:       ruleNewModel,
				confidence: finding.ConfidenceMedium,
				severity:   severity,
				flags:      []finding.Flag{finding.FlagInferred},
				unproven:   []string{"Whether the model change was planned."},
				title: fmt.Sprintf("%s invoked %s for the first time after %d earlier invocations%s",
					event.Principal, event.Model, principalCount[event.Principal], scope),
				events: []source.Event{event},
			})
		}
		principalSeen[event.Principal][event.Model] = true
		accountSeen[event.Account][event.Model] = true
		principalCount[event.Principal] += event.Requests()
	}
}

func (h *hunter) networks() {
	groups, principals := h.byPrincipal(func(e source.Event) bool { return isInvoke(e) && e.SourceIP != "" })
	for _, principal := range principals {
		events := groups[principal]
		h.distinctAddresses(principal, events)
		h.newNetworks(principal, events)
	}
}

func (h *hunter) distinctAddresses(principal string, events []source.Event) {
	for start := 0; start < len(events); start++ {
		addresses := make(map[string]bool)
		end := start
		for end < len(events) && events[end].Time.Sub(events[start].Time) <= h.settings.DistinctIPWindow {
			addresses[events[end].SourceIP] = true
			end++
		}
		if len(addresses) >= h.settings.DistinctIPs {
			h.emit(alert{
				rule:       ruleNetwork,
				confidence: finding.ConfidenceMedium,
				flags:      []finding.Flag{finding.FlagInferred},
				unproven:   []string{"Whether the addresses belong to a legitimate NAT pool or load balancer."},
				title: fmt.Sprintf("%s called models from %d distinct addresses within %s, above the threshold of %d",
					principal, len(addresses), h.settings.DistinctIPWindow, h.settings.DistinctIPs),
				events: events[start:end],
			})
			start = end - 1
		}
	}
}

func (h *hunter) classOf(address string) string {
	if network, ok := h.options.Networks.Lookup(address); ok {
		return network.Class
	}
	return ""
}

func (h *hunter) newNetworks(principal string, events []source.Event) {
	seen := make(map[string]bool)
	history := 0
	nonHostingOnly := true
	for _, event := range events {
		prefix, ok := networkOf(event.SourceIP)
		if !ok {
			continue
		}
		class := h.classOf(event.SourceIP)
		if class == ClassHosting && nonHostingOnly && history >= h.settings.MinHistory && h.options.Networks.Configured() {
			h.emit(alert{
				rule:       ruleNetwork,
				confidence: finding.ConfidenceMedium,
				flags:      []finding.Flag{finding.FlagInferred},
				unproven:   []string{"Whether a hosting provider is a legitimate part of this workload."},
				title:      fmt.Sprintf("%s called models from a hosting provider address after %d calls from other networks", principal, history),
				events:     []source.Event{event},
			})
		} else if !seen[prefix] && len(seen) > 0 && history >= h.settings.MinHistory {
			h.emit(alert{
				rule:       ruleNetwork,
				confidence: finding.ConfidenceLow,
				flags:      []finding.Flag{finding.FlagInferred},
				unproven:   []string{"Whether the new network is a planned change of egress."},
				title:      fmt.Sprintf("%s called models from the new network %s after %d calls from %d other networks", principal, prefix, history, len(seen)),
				events:     []source.Event{event},
			})
		}
		if class == ClassHosting {
			nonHostingOnly = false
		}
		seen[prefix] = true
		history += event.Requests()
	}
}

func (h *hunter) keyUse() {
	for _, created := range h.events {
		if created.Kind != source.KindKeyCreate || created.Failed || created.KeyID == "" || created.SourceIP == "" {
			continue
		}
		for _, used := range h.events {
			if used.Time.Before(created.Time) || used.Time.Sub(created.Time) > h.settings.KeyUseWindow {
				continue
			}
			if used.KeyID != created.KeyID || used.ID == created.ID || used.SourceIP == "" || used.SourceIP == created.SourceIP {
				continue
			}
			h.emit(alert{
				rule:       ruleKeyUse,
				confidence: finding.ConfidenceHigh,
				title: fmt.Sprintf("Key %s was created from %s and used from %s %s later", created.KeyID, created.SourceIP, used.SourceIP,
					used.Time.Sub(created.Time).Round(time.Second)),
				events: []source.Event{created, used},
			})
			break
		}
	}
}

func (h *hunter) reconnaissance() {
	groups, principals := h.byPrincipal(func(source.Event) bool { return true })
	for _, principal := range principals {
		events := groups[principal]
		h.listThenFirstInvoke(principal, events)
		h.loggingRemoval(principal, events)
	}
}

func (h *hunter) listThenFirstInvoke(principal string, events []source.Event) {
	var lists []source.Event
	for _, event := range events {
		switch {
		case event.Kind == source.KindList:
			lists = append(lists, event)
		case isInvoke(event):
			if len(lists) > 0 && event.Time.Sub(lists[0].Time) <= h.settings.ReconWindow {
				h.emit(alert{
					rule:       ruleRecon,
					confidence: finding.ConfidenceMedium,
					flags:      []finding.Flag{finding.FlagInferred},
					unproven:   []string{"Whether a deployment or developer ran the listing as part of normal setup."},
					title:      fmt.Sprintf("%s listed models or quotas %d time(s) and made its first invocation %s later", principal, len(lists), event.Time.Sub(lists[0].Time).Round(time.Second)),
					events:     append(append([]source.Event(nil), lists...), event),
				})
			}
			return
		}
	}
}

func (h *hunter) loggingRemoval(principal string, events []source.Event) {
	for _, read := range events {
		if read.Kind != source.KindLoggingRead {
			continue
		}
		for _, deleted := range events {
			if deleted.Kind == source.KindLoggingDelete && !deleted.Failed && !deleted.Time.Before(read.Time) && deleted.Time.Sub(read.Time) <= h.settings.ReconWindow {
				h.emit(alert{
					rule:       ruleRecon,
					confidence: finding.ConfidenceHigh,
					severity:   finding.SeverityHigh,
					title:      fmt.Sprintf("%s read the invocation logging configuration and deleted it %s later", principal, deleted.Time.Sub(read.Time).Round(time.Second)),
					events:     []source.Event{read, deleted},
				})
				break
			}
		}
	}
}

func (h *hunter) unmapped() {
	owned := h.options.Config
	reportedAccounts := make(map[string]bool)
	reportedServices := make(map[string]bool)
	for _, event := range h.events {
		if !isInvoke(event) || event.Principal == "" {
			continue
		}
		if len(owned.OwnedAccounts) > 0 && event.Account != "" && !owned.OwnsAccount(event.Account) && !reportedAccounts[event.Account+"|"+event.Principal] {
			reportedAccounts[event.Account+"|"+event.Principal] = true
			h.emit(alert{
				rule:       ruleUnmapped,
				confidence: finding.ConfidenceHigh,
				severity:   finding.SeverityHigh,
				flags:      []finding.Flag{finding.FlagConfigImplied},
				title:      fmt.Sprintf("%s invoked models in account %s, which is not listed in owned_accounts", event.Principal, event.Account),
				events:     []source.Event{event},
			})
		}
		providers, mapped := serviceProviders[event.Service]
		key := event.Principal + "|" + event.Service
		if !h.options.Code.Loaded || !mapped || reportedServices[key] || anyProvider(h.options.Code.Providers, providers) {
			continue
		}
		reportedServices[key] = true
		h.emit(alert{
			rule:       ruleUnmapped,
			confidence: finding.ConfidenceMedium,
			flags:      []finding.Flag{finding.FlagInferred},
			unproven:   []string{"Whether the code that uses this service is outside the scanned repositories."},
			title:      fmt.Sprintf("%s invoked %s, but no scanned code calls that service", event.Principal, event.Service),
			events:     []source.Event{event},
		})
	}
}

func anyProvider(used map[string]bool, providers []string) bool {
	for _, provider := range providers {
		if used[provider] {
			return true
		}
	}
	return false
}

func (h *hunter) streaming() {
	groups, principals := h.byPrincipal(func(e source.Event) bool { return isInvoke(e) && e.Streaming })
	for _, principal := range principals {
		events := groups[principal]
		for start := 0; start < len(events); start++ {
			end := start
			uniform := make(map[string]int)
			for end < len(events) && events[end].Time.Sub(events[start].Time) <= h.settings.StreamWindow {
				uniform[events[end].Model+"|"+events[end].UserAgent]++
				end++
			}
			window := events[start:end]
			if len(window) < h.settings.StreamConcurrency {
				continue
			}
			top := 0
			for _, count := range uniform {
				top = max(top, count)
			}
			share := float64(top) / float64(len(window))
			if share < h.settings.UniformShare {
				continue
			}
			h.emit(alert{
				rule:       ruleStreaming,
				confidence: finding.ConfidenceMedium,
				flags:      []finding.Flag{finding.FlagInferred},
				unproven:   []string{"Whether a batch job or load test accounts for the burst."},
				title: fmt.Sprintf("%s sent %d streaming requests within %s, %.0f%% with the same model and client, above the threshold of %d",
					principal, len(window), h.settings.StreamWindow, share*100, h.settings.StreamConcurrency),
				events: window,
			})
			start = end - 1
		}
	}
}
