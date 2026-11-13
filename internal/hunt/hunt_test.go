package hunt

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ryankshah/jackproof/internal/config"
	"github.com/ryankshah/jackproof/internal/finding"
	"github.com/ryankshah/jackproof/internal/hunt/source"
	"github.com/ryankshah/jackproof/internal/rules"
)

var origin = time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)

type eventOption func(*source.Event)

var counter int

func event(offset time.Duration, principal string, kind source.Kind, options ...eventOption) source.Event {
	counter++
	e := source.Event{
		ID: fmt.Sprintf("evt-%d", counter), Time: origin.Add(offset), Source: source.TypeCloudTrail, Principal: principal,
		Account: "111122223333", Action: string(kind), Service: "bedrock", Kind: kind, SourceIP: "203.0.113.5",
	}
	for _, option := range options {
		option(&e)
	}
	return e
}

func withModel(model string) eventOption     { return func(e *source.Event) { e.Model = model } }
func withIP(address string) eventOption      { return func(e *source.Event) { e.SourceIP = address } }
func withSource(name string) eventOption     { return func(e *source.Event) { e.Source = name } }
func withKey(id string) eventOption          { return func(e *source.Event) { e.KeyID = id } }
func withCount(n int) eventOption            { return func(e *source.Event) { e.Count = n } }
func withCost(cost float64) eventOption      { return func(e *source.Event) { e.Cost = cost } }
func withAccount(account string) eventOption { return func(e *source.Event) { e.Account = account } }
func withService(service string) eventOption { return func(e *source.Event) { e.Service = service } }
func withUserAgent(agent string) eventOption { return func(e *source.Event) { e.UserAgent = agent } }
func streaming() eventOption                 { return func(e *source.Event) { e.Streaming = true } }
func failed() eventOption                    { return func(e *source.Event) { e.Failed = true } }

func loadRules(t *testing.T) *rules.Catalogue {
	t.Helper()
	ruleSet, err := rules.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	return ruleSet
}

func analyze(t *testing.T, configYAML string, code CodeMap, networks *Networks, events ...source.Event) []finding.Finding {
	t.Helper()
	cfg, err := config.Parse([]byte(configYAML))
	if err != nil {
		t.Fatal(err)
	}
	findings, err := Analyze(events, Options{Config: cfg, Rules: loadRules(t), Networks: networks, Code: code})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if err := f.Validate(); err != nil {
			t.Errorf("finding %s (%s) is invalid: %v", f.ID, f.Rule, err)
		}
		if f.Module != finding.ModuleHunt || f.Method != finding.MethodLogCorrelation {
			t.Errorf("finding %s has module %s and method %s", f.ID, f.Module, f.Method)
		}
	}
	return findings
}

func ofRule(findings []finding.Finding, id string) []finding.Finding {
	var matched []finding.Finding
	for _, f := range findings {
		if f.Rule == id {
			matched = append(matched, f)
		}
	}
	return matched
}

const role = "arn:aws:iam::111122223333:role/chat"

func TestEnableThenInvoke(t *testing.T) {
	tests := []struct {
		name   string
		events []source.Event
		want   int
	}{
		{"invoke soon after enable", []source.Event{event(0, role, source.KindEnable), event(30*time.Minute, role, source.KindInvoke)}, 1},
		{"invoke too late", []source.Event{event(0, role, source.KindEnable), event(3*time.Hour, role, source.KindInvoke)}, 0},
		{"invoke before enable", []source.Event{event(0, role, source.KindInvoke), event(10*time.Minute, role, source.KindEnable)}, 0},
		{"other principal invokes", []source.Event{event(0, role, source.KindEnable), event(time.Minute, "other", source.KindInvoke)}, 0},
		{"enable failed", []source.Event{event(0, role, source.KindEnable, failed()), event(time.Minute, role, source.KindInvoke)}, 0},
		{"invoke failed", []source.Event{event(0, role, source.KindEnable), event(time.Minute, role, source.KindInvoke, failed())}, 0},
		{"different cloud", []source.Event{event(0, role, source.KindEnable), event(time.Minute, role, source.KindInvoke, withSource(source.TypeGCP))}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			found := ofRule(analyze(t, "", CodeMap{}, nil, tt.events...), "JP-HUNT-001")
			if len(found) != tt.want {
				t.Fatalf("got %d findings, want %d: %+v", len(found), tt.want, found)
			}
			if tt.want == 1 {
				if found[0].Confidence != finding.ConfidenceHigh || len(found[0].Evidence) != 2 || found[0].Evidence[0].Record == "" || found[0].Evidence[0].Timestamp.IsZero() {
					t.Errorf("finding = %+v", found[0])
				}
			}
		})
	}
}

func TestEnableWindowIsConfigurable(t *testing.T) {
	events := []source.Event{event(0, role, source.KindEnable), event(3*time.Hour, role, source.KindInvoke)}
	found := ofRule(analyze(t, "hunt:\n  enable_then_invoke_window: 4h\n", CodeMap{}, nil, events...), "JP-HUNT-001")
	if len(found) != 1 {
		t.Errorf("got %d findings with a 4h window, want 1", len(found))
	}
}

func steadyHours(hours, perHour int) []source.Event {
	var events []source.Event
	for hour := 0; hour < hours; hour++ {
		events = append(events, event(time.Duration(hour)*time.Hour+time.Minute, role, source.KindInvoke, withCount(perHour), withModel("m1")))
	}
	return events
}

func TestVolumeSpike(t *testing.T) {
	tests := []struct {
		name  string
		build func() []source.Event
		want  int
	}{
		{"spike over baseline", func() []source.Event {
			return append(steadyHours(6, 10), event(6*time.Hour+time.Minute, role, source.KindInvoke, withCount(100), withModel("m1")))
		}, 1},
		{"within multiplier", func() []source.Event {
			return append(steadyHours(6, 10), event(6*time.Hour+time.Minute, role, source.KindInvoke, withCount(40), withModel("m1")))
		}, 0},
		{"too little history", func() []source.Event {
			return append(steadyHours(2, 10), event(2*time.Hour+time.Minute, role, source.KindInvoke, withCount(100), withModel("m1")))
		}, 0},
		{"below the minimum request count", func() []source.Event {
			return append(steadyHours(6, 1), event(6*time.Hour+time.Minute, role, source.KindInvoke, withCount(15), withModel("m1")))
		}, 0},
		{"failed calls are ignored", func() []source.Event {
			return append(steadyHours(6, 10), event(6*time.Hour+time.Minute, role, source.KindInvoke, withCount(100), failed()))
		}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			found := ofRule(analyze(t, "", CodeMap{}, nil, tt.build()...), "JP-HUNT-002")
			if len(found) != tt.want {
				t.Fatalf("got %d findings, want %d: %+v", len(found), tt.want, found)
			}
			if tt.want == 1 {
				title := found[0].Title
				for _, want := range []string{"100 requests", "baseline median of 10", "6 earlier periods", "10.0 times"} {
					if !strings.Contains(title, want) {
						t.Errorf("title lacks %q: %s", want, title)
					}
				}
			}
		})
	}
}

func TestCostSpike(t *testing.T) {
	var events []source.Event
	for hour := 0; hour < 5; hour++ {
		events = append(events, event(time.Duration(hour)*time.Hour, "key-1", source.KindInvoke, withCount(1), withCost(2)))
	}
	events = append(events, event(5*time.Hour, "key-1", source.KindInvoke, withCount(1), withCost(60)))
	found := ofRule(analyze(t, "", CodeMap{}, nil, events...), "JP-HUNT-002")
	if len(found) != 1 || !strings.Contains(found[0].Title, "spent 60.00") || !strings.Contains(found[0].Title, "baseline median of 2.00") {
		t.Fatalf("findings = %+v", found)
	}
}

func TestFirstSeenModels(t *testing.T) {
	history := func(principal string) []source.Event {
		var events []source.Event
		for i := 0; i < 25; i++ {
			events = append(events, event(time.Duration(i)*time.Minute, principal, source.KindInvoke, withModel("claude-3-haiku")))
		}
		return events
	}
	tests := []struct {
		name         string
		extra        []source.Event
		want         int
		wantSeverity finding.Severity
	}{
		{"new model in the account", []source.Event{event(time.Hour, role, source.KindInvoke, withModel("claude-3-sonnet"))}, 1, finding.SeverityMedium},
		{"new high cost model", []source.Event{event(time.Hour, role, source.KindInvoke, withModel("claude-3-opus"))}, 1, finding.SeverityHigh},
		{"known model", []source.Event{event(time.Hour, role, source.KindInvoke, withModel("claude-3-haiku"))}, 0, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			events := append(history(role), tt.extra...)
			found := ofRule(analyze(t, "", CodeMap{}, nil, events...), "JP-HUNT-003")
			if len(found) != tt.want {
				t.Fatalf("got %d findings, want %d: %+v", len(found), tt.want, found)
			}
			if tt.want == 1 && found[0].Severity != tt.wantSeverity {
				t.Errorf("severity = %s, want %s", found[0].Severity, tt.wantSeverity)
			}
		})
	}
}

func TestFirstSeenModelNeedsHistory(t *testing.T) {
	events := []source.Event{
		event(0, role, source.KindInvoke, withModel("a")),
		event(time.Minute, role, source.KindInvoke, withModel("claude-3-opus")),
	}
	if found := ofRule(analyze(t, "", CodeMap{}, nil, events...), "JP-HUNT-003"); len(found) != 0 {
		t.Errorf("got %d findings without history, want 0", len(found))
	}
}

func TestManyAddresses(t *testing.T) {
	addresses := func(n int) []source.Event {
		var events []source.Event
		for i := 0; i < n; i++ {
			events = append(events, event(time.Duration(i)*30*time.Second, role, source.KindInvoke, withIP(fmt.Sprintf("198.51.%d.7", 100+i))))
		}
		return events
	}
	if found := ofRule(analyze(t, "", CodeMap{}, nil, addresses(6)...), "JP-HUNT-004"); len(found) != 1 || !strings.Contains(found[0].Title, "6 distinct addresses") {
		t.Errorf("six addresses: %+v", found)
	}
	if found := ofRule(analyze(t, "", CodeMap{}, nil, addresses(3)...), "JP-HUNT-004"); len(found) != 0 {
		t.Errorf("three addresses produced %d findings", len(found))
	}
	spread := addresses(6)
	for i := range spread {
		spread[i].Time = origin.Add(time.Duration(i) * time.Hour)
	}
	if found := ofRule(analyze(t, "", CodeMap{}, nil, spread...), "JP-HUNT-004"); len(found) != 0 {
		t.Errorf("addresses spread over hours produced %d findings", len(found))
	}
}

func TestNewAndHostingNetworks(t *testing.T) {
	history := func(address string) []source.Event {
		var events []source.Event
		for i := 0; i < 25; i++ {
			events = append(events, event(time.Duration(i)*time.Minute, role, source.KindInvoke, withIP(address)))
		}
		return events
	}
	networks, err := NewNetworks([]string{"203.0.113.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	if err := networks.LoadMap([]byte("cidr,asn,org,class\n198.51.100.0/24,AS64500,Example Hosting,hosting\n")); err != nil {
		t.Fatal(err)
	}

	hosting := append(history("203.0.113.5"), event(time.Hour, role, source.KindInvoke, withIP("198.51.100.20")))
	found := ofRule(analyze(t, "", CodeMap{}, networks, hosting...), "JP-HUNT-004")
	if len(found) != 1 || !strings.Contains(found[0].Title, "hosting provider") {
		t.Errorf("hosting: %+v", found)
	}

	newNetwork := append(history("203.0.113.5"), event(time.Hour, role, source.KindInvoke, withIP("192.0.2.77")))
	found = ofRule(analyze(t, "", CodeMap{}, nil, newNetwork...), "JP-HUNT-004")
	if len(found) != 1 || found[0].Confidence != finding.ConfidenceLow || !strings.Contains(found[0].Title, "192.0.2.0/24") {
		t.Errorf("new network: %+v", found)
	}

	same := append(history("203.0.113.5"), event(time.Hour, role, source.KindInvoke, withIP("203.0.113.90")))
	if found := ofRule(analyze(t, "", CodeMap{}, nil, same...), "JP-HUNT-004"); len(found) != 0 {
		t.Errorf("same network: %+v", found)
	}

	private := append(history("203.0.113.5"), event(time.Hour, role, source.KindInvoke, withIP("10.1.2.3")))
	if found := ofRule(analyze(t, "", CodeMap{}, nil, private...), "JP-HUNT-004"); len(found) != 0 {
		t.Errorf("private address: %+v", found)
	}
}

func TestKeyCreatedThenUsedElsewhere(t *testing.T) {
	tests := []struct {
		name   string
		events []source.Event
		want   int
	}{
		{"used from a new address", []source.Event{event(0, role, source.KindKeyCreate, withKey("AKIA1")), event(5*time.Minute, "arn:user/x", source.KindInvoke, withKey("AKIA1"), withIP("198.51.100.9"))}, 1},
		{"used from the same address", []source.Event{event(0, role, source.KindKeyCreate, withKey("AKIA1")), event(5*time.Minute, "arn:user/x", source.KindInvoke, withKey("AKIA1"))}, 0},
		{"used too late", []source.Event{event(0, role, source.KindKeyCreate, withKey("AKIA1")), event(time.Hour, "arn:user/x", source.KindInvoke, withKey("AKIA1"), withIP("198.51.100.9"))}, 0},
		{"another key", []source.Event{event(0, role, source.KindKeyCreate, withKey("AKIA1")), event(time.Minute, "arn:user/x", source.KindInvoke, withKey("AKIA2"), withIP("198.51.100.9"))}, 0},
		{"no key id", []source.Event{event(0, role, source.KindKeyCreate), event(time.Minute, "arn:user/x", source.KindInvoke, withIP("198.51.100.9"))}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			found := ofRule(analyze(t, "", CodeMap{}, nil, tt.events...), "JP-HUNT-005")
			if len(found) != tt.want {
				t.Fatalf("got %d findings, want %d: %+v", len(found), tt.want, found)
			}
		})
	}
}

func TestReconnaissance(t *testing.T) {
	tests := []struct {
		name     string
		events   []source.Event
		want     int
		severity finding.Severity
	}{
		{"list then first invoke", []source.Event{event(0, role, source.KindList), event(time.Minute, role, source.KindList), event(10*time.Minute, role, source.KindInvoke)}, 1, finding.SeverityMedium},
		{"invoke before list", []source.Event{event(0, role, source.KindInvoke), event(time.Minute, role, source.KindList), event(2*time.Minute, role, source.KindInvoke)}, 0, ""},
		{"list far from first invoke", []source.Event{event(0, role, source.KindList), event(3*time.Hour, role, source.KindInvoke)}, 0, ""},
		{"logging read then deleted", []source.Event{event(0, role, source.KindLoggingRead), event(2*time.Minute, role, source.KindLoggingDelete)}, 1, finding.SeverityHigh},
		{"logging deleted without read", []source.Event{event(0, role, source.KindLoggingDelete)}, 0, ""},
		{"logging deleted by someone else", []source.Event{event(0, role, source.KindLoggingRead), event(time.Minute, "other", source.KindLoggingDelete)}, 0, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			found := ofRule(analyze(t, "", CodeMap{}, nil, tt.events...), "JP-HUNT-006")
			if len(found) != tt.want {
				t.Fatalf("got %d findings, want %d: %+v", len(found), tt.want, found)
			}
			if tt.want == 1 && found[0].Severity != tt.severity {
				t.Errorf("severity = %s, want %s", found[0].Severity, tt.severity)
			}
		})
	}
}

func TestUnmappedPrincipals(t *testing.T) {
	tests := []struct {
		name       string
		configYAML string
		code       CodeMap
		events     []source.Event
		want       int
		wantFlag   finding.Flag
	}{
		{"account not owned", "owned_accounts: [\"999900009999\"]\n", CodeMap{}, []source.Event{event(0, role, source.KindInvoke)}, 1, finding.FlagConfigImplied},
		{"account owned", "owned_accounts: [\"111122223333\"]\n", CodeMap{}, []source.Event{event(0, role, source.KindInvoke)}, 0, ""},
		{"no owned accounts configured", "", CodeMap{}, []source.Event{event(0, role, source.KindInvoke)}, 0, ""},
		{"code does not call the service", "", CodeMap{Loaded: true, Providers: map[string]bool{"openai": true}}, []source.Event{event(0, role, source.KindInvoke)}, 1, finding.FlagInferred},
		{"code calls the service", "", CodeMap{Loaded: true, Providers: map[string]bool{"aws": true}}, []source.Event{event(0, role, source.KindInvoke)}, 0, ""},
		{"graph not provided", "", CodeMap{}, []source.Event{event(0, role, source.KindInvoke)}, 0, ""},
		{"service without a code provider", "", CodeMap{Loaded: true, Providers: map[string]bool{}}, []source.Event{event(0, role, source.KindInvoke, withService("usage"))}, 0, ""},
		{"failed calls are ignored", "owned_accounts: [\"999900009999\"]\n", CodeMap{}, []source.Event{event(0, role, source.KindInvoke, failed())}, 0, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			found := ofRule(analyze(t, tt.configYAML, tt.code, nil, tt.events...), "JP-HUNT-007")
			if len(found) != tt.want {
				t.Fatalf("got %d findings, want %d: %+v", len(found), tt.want, found)
			}
			if tt.want == 1 && !hasFlag(found[0], tt.wantFlag) {
				t.Errorf("flags = %v, want %s", found[0].Flags, tt.wantFlag)
			}
		})
	}
	duplicate := []source.Event{event(0, role, source.KindInvoke, withAccount("999900009999")), event(time.Minute, role, source.KindInvoke, withAccount("999900009999"))}
	if found := ofRule(analyze(t, "owned_accounts: [\"111122223333\"]\n", CodeMap{}, nil, duplicate...), "JP-HUNT-007"); len(found) != 1 {
		t.Errorf("repeated calls from one unowned account produced %d findings, want 1", len(found))
	}
}

func hasFlag(f finding.Finding, flag finding.Flag) bool {
	for _, candidate := range f.Flags {
		if candidate == flag {
			return true
		}
	}
	return false
}

func TestStreamingBurst(t *testing.T) {
	burst := func(n int, model func(int) string) []source.Event {
		var events []source.Event
		for i := 0; i < n; i++ {
			events = append(events, event(time.Duration(i)*time.Second, role, source.KindInvoke, streaming(), withModel(model(i)), withUserAgent("proxy/1.0")))
		}
		return events
	}
	uniform := func(int) string { return "claude-3-haiku" }
	mixed := func(i int) string { return fmt.Sprintf("model-%d", i%4) }
	if found := ofRule(analyze(t, "", CodeMap{}, nil, burst(30, uniform)...), "JP-HUNT-008"); len(found) != 1 || !strings.Contains(found[0].Title, "30 streaming requests") {
		t.Errorf("uniform burst: %+v", found)
	}
	if found := ofRule(analyze(t, "", CodeMap{}, nil, burst(30, mixed)...), "JP-HUNT-008"); len(found) != 0 {
		t.Errorf("mixed models produced %d findings", len(found))
	}
	if found := ofRule(analyze(t, "", CodeMap{}, nil, burst(10, uniform)...), "JP-HUNT-008"); len(found) != 0 {
		t.Errorf("a small burst produced %d findings", len(found))
	}
	nonStreaming := burst(30, uniform)
	for i := range nonStreaming {
		nonStreaming[i].Streaming = false
	}
	if found := ofRule(analyze(t, "", CodeMap{}, nil, nonStreaming...), "JP-HUNT-008"); len(found) != 0 {
		t.Errorf("non streaming requests produced %d findings", len(found))
	}
}

func TestAnalyzeRequiresHuntRules(t *testing.T) {
	empty, err := rules.Load(emptyFS{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Analyze(nil, Options{Config: config.Default(), Rules: empty}); err == nil {
		t.Error("expected an error for a catalogue without the hunt rules")
	}
}

func TestEvidenceIsCappedAndFindingsAreSorted(t *testing.T) {
	var events []source.Event
	for i := 0; i < 40; i++ {
		events = append(events, event(time.Duration(i)*time.Second, role, source.KindInvoke, streaming(), withModel("m"), withIP(fmt.Sprintf("198.51.%d.1", 100+i%10))))
	}
	findings := analyze(t, "", CodeMap{}, nil, events...)
	if len(findings) < 2 {
		t.Fatalf("expected the burst and address findings, got %d", len(findings))
	}
	for _, f := range findings {
		if len(f.Evidence) > maxEvidence {
			t.Errorf("%s has %d evidence entries", f.Rule, len(f.Evidence))
		}
	}
	for i := 1; i < len(findings); i++ {
		if findings[i-1].Severity != findings[i].Severity && !findings[i-1].Severity.AtLeast(findings[i].Severity) {
			t.Errorf("findings are not sorted by severity: %s before %s", findings[i-1].Severity, findings[i].Severity)
		}
	}
}

func TestMedian(t *testing.T) {
	tests := []struct {
		values []float64
		want   float64
	}{{[]float64{3}, 3}, {[]float64{1, 3}, 2}, {[]float64{5, 1, 3}, 3}, {[]float64{4, 1, 3, 2}, 2.5}}
	for _, tt := range tests {
		if got := median(tt.values); got != tt.want {
			t.Errorf("median(%v) = %v, want %v", tt.values, got, tt.want)
		}
	}
}

func TestNetworks(t *testing.T) {
	networks, err := NewNetworks([]string{"203.0.113.0/24", "2001:db8::/32"})
	if err != nil {
		t.Fatal(err)
	}
	data := "# comment\ncidr,asn,org,class\n198.51.100.0/24,AS1,Broad,hosting\n198.51.100.128/25,AS2,Narrow,corporate\n"
	if err := networks.LoadMap([]byte(data)); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		address string
		want    string
		found   bool
	}{
		{"203.0.113.9", ClassCorporate, true},
		{"198.51.100.5", ClassHosting, true},
		{"198.51.100.200", ClassCorporate, true},
		{"2001:db8::1", ClassCorporate, true},
		{"192.0.2.1", "", false},
		{"not an address", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.address, func(t *testing.T) {
			network, ok := networks.Lookup(tt.address)
			if ok != tt.found || network.Class != tt.want {
				t.Errorf("got %+v, %v", network, ok)
			}
		})
	}
	if !networks.Configured() || (*Networks)(nil).Configured() {
		t.Error("Configured gave the wrong answer")
	}
	if _, ok := (*Networks)(nil).Lookup("1.2.3.4"); ok {
		t.Error("a nil network table must not match")
	}
}

func TestNetworkErrors(t *testing.T) {
	if _, err := NewNetworks([]string{"not-a-cidr"}); err == nil {
		t.Error("expected an error for a bad known network")
	}
	networks, _ := NewNetworks(nil)
	for _, data := range []string{"203.0.113.0/24,AS1,Org\n", "cidr,asn,org,class\nbad,AS1,Org,hosting\n"} {
		if err := networks.LoadMap([]byte(data)); err == nil {
			t.Errorf("expected an error for %q", data)
		}
	}
}

func TestNetworkOf(t *testing.T) {
	tests := []struct {
		address string
		want    string
		ok      bool
	}{
		{"203.0.113.77", "203.0.113.0/24", true},
		{"2001:db8:1:2::5", "2001:db8:1::/48", true},
		{"10.0.0.1", "", false},
		{"127.0.0.1", "", false},
		{"bedrock.amazonaws.com", "", false},
		{"", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.address, func(t *testing.T) {
			got, ok := networkOf(tt.address)
			if got != tt.want || ok != tt.ok {
				t.Errorf("got %q, %v", got, ok)
			}
		})
	}
}

func TestFirstSeenModelForPrincipalOnlyIsLowSeverity(t *testing.T) {
	var events []source.Event
	for i := 0; i < 25; i++ {
		events = append(events, event(time.Duration(i)*time.Minute, role, source.KindInvoke, withModel("claude-3-haiku")))
		events = append(events, event(time.Duration(i)*time.Minute, "arn:aws:iam::111122223333:role/batch", source.KindInvoke, withModel("claude-3-sonnet")))
	}
	events = append(events, event(2*time.Hour, role, source.KindInvoke, withModel("claude-3-sonnet")))
	found := ofRule(analyze(t, "", CodeMap{}, nil, events...), "JP-HUNT-003")
	if len(found) != 1 || found[0].Severity != finding.SeverityLow {
		t.Fatalf("findings = %+v", found)
	}
	if strings.Contains(found[0].Title, "no other principal") {
		t.Errorf("title claims the model was new to the account: %s", found[0].Title)
	}
}
