package posture

import (
	"io/fs"
	"reflect"
	"strings"
	"testing"
)

type emptyFS struct{}

func (emptyFS) Open(name string) (fs.File, error) {
	return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
}

func (emptyFS) ReadDir(string) ([]fs.DirEntry, error) {
	return nil, nil
}

func TestGlobMatches(t *testing.T) {
	tests := []struct {
		pattern string
		value   string
		want    bool
	}{
		{"*", "bedrock:InvokeModel", true},
		{"bedrock:*", "bedrock:InvokeModel", true},
		{"bedrock:*", "BEDROCK:invokemodel", true},
		{"bedrock:Invoke*", "bedrock:InvokeModelWithResponseStream", true},
		{"bedrock:Invoke*", "bedrock:Converse", false},
		{"bedrock:InvokeMode?", "bedrock:InvokeModel", true},
		{"iam:*", "bedrock:InvokeModel", false},
		{"bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream", false},
		{"serviceusage.services.enable", "serviceusage.services.enable", true},
		{"aiplatform.*", "aiplatform.endpoints.predict", true},
	}
	for _, tt := range tests {
		t.Run(tt.pattern+" "+tt.value, func(t *testing.T) {
			if got := globMatches(tt.pattern, tt.value); got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMatchedActions(t *testing.T) {
	got := matchedActions([]string{"bedrock:Invoke*", "s3:GetObject"}, []string{"bedrock:InvokeModel", "bedrock:Converse"})
	if !reflect.DeepEqual(got, []string{"bedrock:InvokeModel"}) {
		t.Errorf("got %v", got)
	}
	if got := matchedActions(nil, []string{"bedrock:InvokeModel"}); len(got) != 0 {
		t.Errorf("got %v", got)
	}
}

func TestKnowledgeIsComplete(t *testing.T) {
	knowledge, err := LoadKnowledge()
	if err != nil {
		t.Fatal(err)
	}
	for _, cloud := range []Cloud{CloudAWS, CloudGCP, CloudAzure} {
		for _, name := range []string{capabilityEnable, capabilityInvoke} {
			if len(knowledge.capabilityActions(name, cloud)) == 0 {
				t.Errorf("no %s actions for %s", name, cloud)
			}
		}
		if len(knowledge.servicesFor(capabilityEnable, cloud)) == 0 {
			t.Errorf("no enable services for %s", cloud)
		}
	}
	if len(knowledge.capabilityActions(capabilityLogging, CloudAWS)) == 0 || len(knowledge.capabilityActions(capabilityKeys, CloudGCP)) == 0 {
		t.Error("logging or key creation actions are missing")
	}
	if _, ok := knowledge.managedPolicy("arn:aws:iam::aws:policy/AdministratorAccess"); !ok {
		t.Error("AdministratorAccess is missing")
	}
	if _, ok := knowledge.gcpRole("roles/owner"); !ok {
		t.Error("roles/owner is missing")
	}
	if _, ok := knowledge.azureRole("owner"); !ok {
		t.Error("the Owner role is missing")
	}
	if knowledge.serviceName("bedrock") != "Amazon Bedrock" || knowledge.serviceName("other") != "other" {
		t.Error("serviceName gave the wrong answer")
	}
	if len(knowledge.UnverifiedEntries()) == 0 {
		t.Error("expected unverified entries")
	}
}

func TestParseKnowledgeErrors(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{"invalid yaml", "capabilities: ["},
		{"unknown field", "bogus: 1\n"},
		{"capability without actions", "capabilities:\n  - {name: a, cloud: aws, service: s}\n"},
		{"service without terms", "services:\n  - {id: a, cloud: aws}\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parseKnowledge([]byte(tt.data)); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

func TestRawStrings(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{`"a"`, []string{"a"}},
		{`["a", "b"]`, []string{"a", "b"}},
		{`42`, nil},
		{``, nil},
	}
	for _, tt := range tests {
		t.Run(strings.TrimSpace(tt.input), func(t *testing.T) {
			if got := rawStrings([]byte(tt.input)); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}
