package graph

import (
	"fmt"
	"sort"
)

type CredentialKind string

const (
	KindLiteral   CredentialKind = "literal"
	KindReference CredentialKind = "reference"
)

type HolderKind string

const (
	HolderComposeService HolderKind = "compose-service"
	HolderKubernetes     HolderKind = "kubernetes-workload"
	HolderGitHubJob      HolderKind = "github-actions-job"
	HolderDockerfile     HolderKind = "dockerfile"
	HolderDevcontainer   HolderKind = "devcontainer"
	HolderNotebook       HolderKind = "notebook"
	HolderCode           HolderKind = "code"
)

type Delivery string

const (
	DeliveryEnv       Delivery = "environment"
	DeliveryEnvFile   Delivery = "env-file"
	DeliverySecretRef Delivery = "secret-reference"
	DeliveryBuildArg  Delivery = "build-arg"
	DeliveryImageEnv  Delivery = "image-env"
	DeliveryImageCopy Delivery = "image-copy"
	DeliveryCodeRead  Delivery = "code-read"
)

type Location struct {
	Path string `json:"path"`
	Line int    `json:"line"`
}

type Credential struct {
	Key         string            `json:"key"`
	Kind        CredentialKind    `json:"kind"`
	Provider    string            `json:"provider"`
	Reach       string            `json:"reach,omitempty"`
	Name        string            `json:"name,omitempty"`
	Redacted    string            `json:"redacted,omitempty"`
	Fingerprint string            `json:"fingerprint,omitempty"`
	Digests     map[string]string `json:"-"`
	Definitions []Location        `json:"definitions,omitempty"`
}

type Holder struct {
	ID              string     `json:"id"`
	Kind            HolderKind `json:"kind"`
	Name            string     `json:"name"`
	Location        Location   `json:"location"`
	Environment     string     `json:"environment,omitempty"`
	Untrusted       bool       `json:"untrusted,omitempty"`
	UntrustedReason string     `json:"untrusted_reason,omitempty"`
	UntrustedProven bool       `json:"untrusted_proven,omitempty"`
	Sinks           []Sink     `json:"sinks,omitempty"`
	Providers       []string   `json:"providers,omitempty"`
}

type SinkKind string

const (
	SinkTelemetry SinkKind = "telemetry"
	SinkEnvDump   SinkKind = "environment-dump"
)

type Sink struct {
	Kind     SinkKind `json:"kind"`
	Detail   string   `json:"detail"`
	Location Location `json:"location"`
}

type Edge struct {
	Credential string   `json:"credential"`
	Holder     string   `json:"holder"`
	Delivery   Delivery `json:"delivery"`
	Plain      bool     `json:"plain,omitempty"`
	Inferred   bool     `json:"inferred,omitempty"`
	Location   Location `json:"location"`
}

type Graph struct {
	credentials map[string]*Credential
	holders     map[string]*Holder
	edges       []Edge
	edgeKeys    map[string]struct{}
}

func New() *Graph {
	return &Graph{
		credentials: make(map[string]*Credential),
		holders:     make(map[string]*Holder),
		edgeKeys:    make(map[string]struct{}),
	}
}

func CredentialKey(kind CredentialKind, identity string) string {
	return fmt.Sprintf("%s:%s", kind, identity)
}

func (g *Graph) AddCredential(c Credential) {
	existing, ok := g.credentials[c.Key]
	if !ok {
		copied := c
		copied.Definitions = nil
		g.credentials[c.Key] = &copied
		existing = &copied
	}
	for _, definition := range c.Definitions {
		if !containsLocation(existing.Definitions, definition) {
			existing.Definitions = append(existing.Definitions, definition)
		}
	}
}

func (g *Graph) AddHolder(h Holder) string {
	if h.ID == "" {
		h.ID = fmt.Sprintf("%s:%s:%s", h.Kind, h.Location.Path, h.Name)
	}
	if existing, ok := g.holders[h.ID]; ok {
		return existing.ID
	}
	copied := h
	g.holders[h.ID] = &copied
	return h.ID
}

func (g *Graph) UpdateHolder(id string, update func(*Holder)) {
	if holder, ok := g.holders[id]; ok {
		update(holder)
	}
}

func (g *Graph) AddEdge(e Edge) {
	key := fmt.Sprintf("%s|%s|%s|%s|%d", e.Credential, e.Holder, e.Delivery, e.Location.Path, e.Location.Line)
	if _, seen := g.edgeKeys[key]; seen {
		return
	}
	g.edgeKeys[key] = struct{}{}
	g.edges = append(g.edges, e)
}

func (g *Graph) Credential(key string) (Credential, bool) {
	credential, ok := g.credentials[key]
	if !ok {
		return Credential{}, false
	}
	return *credential, true
}

func (g *Graph) Holder(id string) (Holder, bool) {
	holder, ok := g.holders[id]
	if !ok {
		return Holder{}, false
	}
	return *holder, true
}

func (g *Graph) Credentials() []Credential {
	out := make([]Credential, 0, len(g.credentials))
	for _, credential := range g.credentials {
		out = append(out, *credential)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

func (g *Graph) Holders() []Holder {
	out := make([]Holder, 0, len(g.holders))
	for _, holder := range g.holders {
		out = append(out, *holder)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (g *Graph) Edges() []Edge {
	out := append([]Edge(nil), g.edges...)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Credential != b.Credential {
			return a.Credential < b.Credential
		}
		if a.Holder != b.Holder {
			return a.Holder < b.Holder
		}
		if a.Location.Path != b.Location.Path {
			return a.Location.Path < b.Location.Path
		}
		return a.Location.Line < b.Location.Line
	})
	return out
}

func (g *Graph) EdgesOf(credentialKey string) []Edge {
	var out []Edge
	for _, edge := range g.Edges() {
		if edge.Credential == credentialKey {
			out = append(out, edge)
		}
	}
	return out
}

func (g *Graph) HoldersOf(credentialKey string) []Holder {
	seen := make(map[string]struct{})
	var out []Holder
	for _, edge := range g.EdgesOf(credentialKey) {
		if _, dup := seen[edge.Holder]; dup {
			continue
		}
		seen[edge.Holder] = struct{}{}
		if holder, ok := g.Holder(edge.Holder); ok {
			out = append(out, holder)
		}
	}
	return out
}

func (g *Graph) Environments(credentialKey string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, holder := range g.HoldersOf(credentialKey) {
		if holder.Environment == "" {
			continue
		}
		if _, dup := seen[holder.Environment]; dup {
			continue
		}
		seen[holder.Environment] = struct{}{}
		out = append(out, holder.Environment)
	}
	sort.Strings(out)
	return out
}

func containsLocation(locations []Location, target Location) bool {
	for _, location := range locations {
		if location == target {
			return true
		}
	}
	return false
}
