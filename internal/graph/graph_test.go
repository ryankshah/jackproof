package graph

import (
	"reflect"
	"testing"
)

func buildGraph() *Graph {
	g := New()
	g.AddCredential(Credential{Key: "literal:aaaa", Kind: KindLiteral, Provider: "openai", Definitions: []Location{{"a.env", 1}}})
	g.AddCredential(Credential{Key: "literal:aaaa", Kind: KindLiteral, Provider: "openai", Definitions: []Location{{"a.env", 1}, {"b.env", 4}}})
	g.AddCredential(Credential{Key: "reference:env:OPENAI_API_KEY", Kind: KindReference, Provider: "openai", Name: "OPENAI_API_KEY"})

	dev := g.AddHolder(Holder{Kind: HolderComposeService, Name: "web", Location: Location{"dev/compose.yaml", 3}, Environment: "dev"})
	prod := g.AddHolder(Holder{Kind: HolderComposeService, Name: "web", Location: Location{"prod/compose.yaml", 3}, Environment: "prod"})
	unscoped := g.AddHolder(Holder{Kind: HolderDockerfile, Name: "Dockerfile", Location: Location{"Dockerfile", 1}})

	g.AddEdge(Edge{Credential: "literal:aaaa", Holder: dev, Delivery: DeliveryEnvFile, Location: Location{"dev/compose.yaml", 5}})
	g.AddEdge(Edge{Credential: "literal:aaaa", Holder: prod, Delivery: DeliveryEnv, Plain: true, Location: Location{"prod/compose.yaml", 6}})
	g.AddEdge(Edge{Credential: "literal:aaaa", Holder: unscoped, Delivery: DeliveryImageEnv, Location: Location{"Dockerfile", 2}})
	g.AddEdge(Edge{Credential: "reference:env:OPENAI_API_KEY", Holder: dev, Delivery: DeliveryEnv, Location: Location{"dev/compose.yaml", 7}})
	return g
}

func TestAddCredentialMergesDefinitions(t *testing.T) {
	g := buildGraph()
	credential, ok := g.Credential("literal:aaaa")
	if !ok {
		t.Fatal("credential missing")
	}
	want := []Location{{"a.env", 1}, {"b.env", 4}}
	if !reflect.DeepEqual(credential.Definitions, want) {
		t.Errorf("definitions = %v, want %v", credential.Definitions, want)
	}
	if len(g.Credentials()) != 2 {
		t.Errorf("credential count = %d, want 2", len(g.Credentials()))
	}
}

func TestAddEdgeDeduplicates(t *testing.T) {
	g := buildGraph()
	before := len(g.Edges())
	g.AddEdge(Edge{Credential: "literal:aaaa", Holder: "compose-service:dev/compose.yaml:web", Delivery: DeliveryEnvFile, Location: Location{"dev/compose.yaml", 5}})
	if len(g.Edges()) != before {
		t.Errorf("edge count changed from %d to %d", before, len(g.Edges()))
	}
}

func TestAddHolderIsIdempotent(t *testing.T) {
	g := New()
	holder := Holder{Kind: HolderGitHubJob, Name: "build", Location: Location{".github/workflows/ci.yml", 8}}
	first := g.AddHolder(holder)
	holder.Environment = "prod"
	second := g.AddHolder(holder)
	if first != second || len(g.Holders()) != 1 {
		t.Errorf("ids %q and %q, holder count %d", first, second, len(g.Holders()))
	}
	stored, _ := g.Holder(first)
	if stored.Environment != "" {
		t.Errorf("second add overwrote the holder: %+v", stored)
	}
}

func TestUpdateHolder(t *testing.T) {
	g := New()
	id := g.AddHolder(Holder{Kind: HolderCode, Name: "main.go", Location: Location{"main.go", 1}})
	g.UpdateHolder(id, func(h *Holder) { h.Untrusted = true })
	g.UpdateHolder("missing", func(h *Holder) { h.Untrusted = true })
	holder, _ := g.Holder(id)
	if !holder.Untrusted {
		t.Error("holder was not updated")
	}
}

func TestQueries(t *testing.T) {
	g := buildGraph()
	tests := []struct {
		name          string
		credential    string
		wantHolders   int
		wantEnvs      []string
		wantEdgeCount int
	}{
		{"literal", "literal:aaaa", 3, []string{"dev", "prod"}, 3},
		{"reference", "reference:env:OPENAI_API_KEY", 1, []string{"dev"}, 1},
		{"unknown", "literal:none", 0, nil, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := len(g.HoldersOf(tt.credential)); got != tt.wantHolders {
				t.Errorf("holders = %d, want %d", got, tt.wantHolders)
			}
			if got := g.Environments(tt.credential); !reflect.DeepEqual(got, tt.wantEnvs) {
				t.Errorf("environments = %v, want %v", got, tt.wantEnvs)
			}
			edges := g.EdgesOf(tt.credential)
			if len(edges) != tt.wantEdgeCount {
				t.Errorf("edges = %d, want %d", len(edges), tt.wantEdgeCount)
			}
		})
	}
}

func TestCredentialKey(t *testing.T) {
	if got := CredentialKey(KindLiteral, "abcd"); got != "literal:abcd" {
		t.Errorf("got %q", got)
	}
	if got := CredentialKey(KindReference, "env:X"); got != "reference:env:X" {
		t.Errorf("got %q", got)
	}
}

func TestOutputsAreSorted(t *testing.T) {
	g := buildGraph()
	credentials := g.Credentials()
	if credentials[0].Key > credentials[1].Key {
		t.Errorf("credentials unsorted: %v", credentials)
	}
	holders := g.Holders()
	for i := 1; i < len(holders); i++ {
		if holders[i-1].ID > holders[i].ID {
			t.Errorf("holders unsorted at %d", i)
		}
	}
}
