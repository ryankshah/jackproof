package source

import (
	"bytes"
	"compress/gzip"
	"strings"
	"testing"
	"time"
)

func ctJSON(name, source, extra string) string {
	return `{"eventVersion":"1.09","eventTime":"2026-03-01T10:00:00Z","eventSource":"` + source + `","eventName":"` + name + `",` +
		`"awsRegion":"us-east-1","sourceIPAddress":"203.0.113.9","userAgent":"aws-sdk-go","eventID":"evt-` + name + `",` +
		`"recipientAccountId":"111122223333","userIdentity":{"type":"AssumedRole","arn":"arn:aws:sts::111122223333:assumed-role/chat/session","accountId":"111122223333","accessKeyId":"ASIAEXAMPLE","sessionContext":{"sessionIssuer":{"arn":"arn:aws:iam::111122223333:role/chat"}}}` + extra + `}`
}

func TestCloudTrail(t *testing.T) {
	records := []string{
		ctJSON("InvokeModel", "bedrock.amazonaws.com", `,"requestParameters":{"modelId":"arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3-haiku"}`),
		ctJSON("ConverseStream", "bedrock.amazonaws.com", `,"requestParameters":{"modelId":"anthropic.claude-3-opus"}`),
		ctJSON("ListFoundationModels", "bedrock.amazonaws.com", ``),
		ctJSON("PutFoundationModelEntitlement", "bedrock.amazonaws.com", `,"errorCode":"AccessDenied"`),
		ctJSON("DeleteModelInvocationLoggingConfiguration", "bedrock.amazonaws.com", ``),
		ctJSON("GetModelInvocationLoggingConfiguration", "bedrock.amazonaws.com", ``),
		ctJSON("Subscribe", "aws-marketplace.amazonaws.com", ``),
		ctJSON("ListServiceQuotas", "servicequotas.amazonaws.com", `,"requestParameters":{"serviceCode":"bedrock"}`),
		ctJSON("ListServiceQuotas", "servicequotas.amazonaws.com", `,"requestParameters":{"serviceCode":"ec2"}`),
		ctJSON("CreateAccessKey", "iam.amazonaws.com", `,"responseElements":{"accessKey":{"accessKeyId":"AKIANEWKEY"}}`),
		ctJSON("DescribeInstances", "ec2.amazonaws.com", ``),
	}
	layouts := map[string]string{
		"records object": `{"Records": [` + strings.Join(records, ",") + `]}`,
		"array":          `[` + strings.Join(records, ",") + `]`,
		"json lines":     strings.Join(records, "\n"),
	}
	for name, content := range layouts {
		t.Run(name, func(t *testing.T) {
			result, err := Load(TypeCloudTrail, "trail.json", []byte(content), UsageOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Events) != 9 {
				t.Fatalf("got %d events, want 9", len(result.Events))
			}
			byAction := make(map[string]Event)
			for _, event := range result.Events {
				byAction[event.Action] = event
			}
			invoke := byAction["InvokeModel"]
			if invoke.Kind != KindInvoke || invoke.Model != "anthropic.claude-3-haiku" || invoke.Principal != "arn:aws:iam::111122223333:role/chat" ||
				invoke.Account != "111122223333" || invoke.SourceIP != "203.0.113.9" || invoke.KeyID != "ASIAEXAMPLE" || invoke.Streaming {
				t.Errorf("InvokeModel = %+v", invoke)
			}
			if stream := byAction["ConverseStream"]; !stream.Streaming || stream.Kind != KindInvoke {
				t.Errorf("ConverseStream = %+v", stream)
			}
			wantKinds := map[string]Kind{
				"ListFoundationModels":                      KindList,
				"PutFoundationModelEntitlement":             KindEnable,
				"DeleteModelInvocationLoggingConfiguration": KindLoggingDelete,
				"GetModelInvocationLoggingConfiguration":    KindLoggingRead,
				"Subscribe":                                 KindEnable,
				"ListServiceQuotas":                         KindList,
				"CreateAccessKey":                           KindKeyCreate,
			}
			for action, kind := range wantKinds {
				if byAction[action].Kind != kind {
					t.Errorf("%s kind = %s, want %s", action, byAction[action].Kind, kind)
				}
			}
			if !byAction["PutFoundationModelEntitlement"].Failed {
				t.Error("an event with an error code must be marked failed")
			}
			if byAction["CreateAccessKey"].KeyID != "AKIANEWKEY" {
				t.Errorf("created key = %q", byAction["CreateAccessKey"].KeyID)
			}
		})
	}
}

func TestCloudTrailGzipAndMalformedRecords(t *testing.T) {
	good := ctJSON("InvokeModel", "bedrock.amazonaws.com", ``)
	bad := `{"eventTime": "not a time", "eventSource": "bedrock.amazonaws.com", "eventName": "InvokeModel"}`
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write([]byte(`{"Records": [` + good + `,` + bad + `, 17]}`)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	result, err := Load(TypeCloudTrail, "trail.json.gz", compressed.Bytes(), UsageOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) != 1 || result.Skipped != 2 {
		t.Errorf("events = %d, skipped = %d", len(result.Events), result.Skipped)
	}
}

func TestEventsAreSortedByTime(t *testing.T) {
	later := strings.Replace(ctJSON("InvokeModel", "bedrock.amazonaws.com", ``), "10:00:00Z", "12:00:00Z", 1)
	earlier := strings.Replace(ctJSON("Converse", "bedrock.amazonaws.com", ``), "10:00:00Z", "09:00:00Z", 1)
	result, err := Load(TypeCloudTrail, "t.json", []byte(`[`+later+`,`+earlier+`]`), UsageOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Events[0].Action != "Converse" || !result.Events[0].Time.Before(result.Events[1].Time) {
		t.Errorf("events = %+v", result.Events)
	}
}

func gcpJSON(method, service, resource, extra string) string {
	return `{"insertId":"ins-` + method + `","timestamp":"2026-03-01T10:00:00.123Z","resource":{"labels":{"project_id":"proj-1"}},` +
		`"protoPayload":{"methodName":"` + method + `","serviceName":"` + service + `","resourceName":"` + resource + `",` +
		`"authenticationInfo":{"principalEmail":"ml@proj-1.iam.gserviceaccount.com","serviceAccountKeyName":"projects/p/serviceAccounts/ml/keys/KEY123"},` +
		`"requestMetadata":{"callerIp":"198.51.100.4","callerSuppliedUserAgent":"google-cloud-sdk"}` + extra + `}}`
}

func TestGCP(t *testing.T) {
	entries := []string{
		gcpJSON("google.cloud.aiplatform.v1.PredictionService.GenerateContent", "aiplatform.googleapis.com", "projects/p/locations/us/publishers/google/models/gemini-1.5-pro", ``),
		gcpJSON("google.cloud.aiplatform.v1.PredictionService.StreamGenerateContent", "aiplatform.googleapis.com", "projects/p/locations/us/publishers/google/models/gemini-1.5-pro", ``),
		gcpJSON("google.cloud.aiplatform.v1.ModelService.ListModels", "aiplatform.googleapis.com", "projects/p", ``),
		gcpJSON("google.api.serviceusage.v1.ServiceUsage.EnableService", "serviceusage.googleapis.com", "projects/123/services/aiplatform.googleapis.com", ``),
		gcpJSON("google.api.serviceusage.v1.ServiceUsage.BatchEnableServices", "serviceusage.googleapis.com", "projects/123", `,"request":{"serviceIds":["storage.googleapis.com","generativelanguage.googleapis.com"]}`),
		gcpJSON("google.api.serviceusage.v1.ServiceUsage.EnableService", "serviceusage.googleapis.com", "projects/123/services/storage.googleapis.com", ``),
		gcpJSON("google.iam.admin.v1.CreateServiceAccountKey", "iam.googleapis.com", "projects/p/serviceAccounts/ml", `,"response":{"name":"projects/p/serviceAccounts/ml/keys/NEWKEY9"}`),
		gcpJSON("storage.objects.get", "storage.googleapis.com", "projects/_/buckets/b", ``),
	}
	result, err := Load(TypeGCP, "audit.json", []byte(`[`+strings.Join(entries, ",")+`]`), UsageOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) != 6 {
		t.Fatalf("got %d events, want 6", len(result.Events))
	}
	var generate, stream, key Event
	enables := 0
	for _, event := range result.Events {
		switch {
		case strings.HasSuffix(event.Action, ".GenerateContent") && !event.Streaming:
			generate = event
		case strings.HasSuffix(event.Action, "StreamGenerateContent"):
			stream = event
		case event.Kind == KindKeyCreate:
			key = event
		case event.Kind == KindEnable:
			enables++
		}
	}
	if generate.Kind != KindInvoke || generate.Model != "gemini-1.5-pro" || generate.Principal != "ml@proj-1.iam.gserviceaccount.com" ||
		generate.Account != "proj-1" || generate.SourceIP != "198.51.100.4" || generate.KeyID != "KEY123" || generate.Service != "vertex-ai" {
		t.Errorf("generate = %+v", generate)
	}
	if !stream.Streaming {
		t.Errorf("stream = %+v", stream)
	}
	if enables != 2 {
		t.Errorf("model enablement events = %d, want 2 (the storage API must not count)", enables)
	}
	if key.KeyID != "NEWKEY9" {
		t.Errorf("created key = %q", key.KeyID)
	}
}

func TestGCPEntriesContainer(t *testing.T) {
	entry := gcpJSON("google.cloud.aiplatform.v1.PredictionService.Predict", "aiplatform.googleapis.com", "publishers/google/models/text-bison", ``)
	result, err := Load(TypeGCP, "a.json", []byte(`{"entries": [`+entry+`]}`), UsageOptions{})
	if err != nil || len(result.Events) != 1 || result.Events[0].Model != "text-bison" {
		t.Errorf("result = %+v, err = %v", result, err)
	}
}

func azureJSON(operation, status string) string {
	return `{"operationName":{"value":"` + operation + `","localizedValue":"x"},"caller":"dev@example.com","eventTimestamp":"2026-03-01T10:00:00Z",` +
		`"eventDataId":"az-` + operation + status + `","subscriptionId":"sub-1","status":{"value":"` + status + `"},"httpRequest":{"clientIpAddress":"192.0.2.10"}}`
}

func TestAzure(t *testing.T) {
	records := []string{
		azureJSON("Microsoft.CognitiveServices/accounts/write", "Started"),
		azureJSON("Microsoft.CognitiveServices/accounts/write", "Succeeded"),
		azureJSON("Microsoft.CognitiveServices/accounts/deployments/write", "Failed"),
		azureJSON("Microsoft.CognitiveServices/accounts/listKeys/action", "Succeeded"),
		azureJSON("Microsoft.Storage/storageAccounts/write", "Succeeded"),
	}
	result, err := Load(TypeAzure, "activity.json", []byte(`{"value": [`+strings.Join(records, ",")+`]}`), UsageOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) != 3 {
		t.Fatalf("got %d events, want 3: %+v", len(result.Events), result.Events)
	}
	kinds := make(map[Kind]int)
	for _, event := range result.Events {
		kinds[event.Kind]++
		if event.Principal != "dev@example.com" || event.Account != "sub-1" || event.SourceIP != "192.0.2.10" {
			t.Errorf("event = %+v", event)
		}
	}
	if kinds[KindEnable] != 2 || kinds[KindKeyCreate] != 1 {
		t.Errorf("kinds = %v", kinds)
	}
	failed := 0
	for _, event := range result.Events {
		if event.Failed {
			failed++
		}
	}
	if failed != 1 {
		t.Errorf("failed events = %d, want 1", failed)
	}
}

func TestAzureStringOperationName(t *testing.T) {
	record := `{"operationName":"Microsoft.CognitiveServices/accounts/write","caller":"c","time":"2026-03-01T10:00:00Z","status":"Succeeded","callerIpAddress":"192.0.2.1"}`
	result, err := Load(TypeAzure, "a.json", []byte(`[`+record+`]`), UsageOptions{})
	if err != nil || len(result.Events) != 1 || result.Events[0].SourceIP != "192.0.2.1" {
		t.Errorf("result = %+v, err = %v", result, err)
	}
}

func TestUsageCSV(t *testing.T) {
	csv := "timestamp,principal,model,requests,cost,source_ip\n" +
		"2026-03-01T10:00:00Z,key-1,gpt-4o,120,$3.50,203.0.113.7\n" +
		"1772359200,key-2,claude-3-opus,5,0.25,\n" +
		"2026-03-02,key-1,gpt-4o,x,1,\n" +
		"not-a-time,key-1,gpt-4o,1,1,\n"
	result, err := Load(TypeUsage, "usage.csv", []byte(csv), UsageOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) != 2 || result.Skipped != 2 {
		t.Fatalf("events = %d, skipped = %d", len(result.Events), result.Skipped)
	}
	first := result.Events[0]
	if first.Kind != KindInvoke || first.Count != 120 || first.Requests() != 120 || first.Cost != 3.5 || first.Principal != "key-1" || first.SourceIP != "203.0.113.7" {
		t.Errorf("first = %+v", first)
	}
	if second := result.Events[1]; second.Time.Unix() != 1772359200 || second.Cost != 0.25 {
		t.Errorf("second = %+v", second)
	}
}

func TestUsageCSVColumnMapping(t *testing.T) {
	columns, err := ParseColumns("timestamp=ts, principal=api_key_id,requests=n")
	if err != nil {
		t.Fatal(err)
	}
	csv := "TS,API_KEY_ID,n,extra\n2026-03-01T10:00:00Z,k1,7,x\n"
	result, err := Load(TypeUsage, "u.csv", []byte(csv), UsageOptions{Columns: columns})
	if err != nil || len(result.Events) != 1 || result.Events[0].Count != 7 || result.Events[0].Principal != "k1" {
		t.Errorf("result = %+v, err = %v", result, err)
	}
	if _, err := Load(TypeUsage, "u.csv", []byte("a,b\n1,2\n"), UsageOptions{}); err == nil {
		t.Error("expected an error for a csv without the required columns")
	}
}

func TestParseColumnsErrors(t *testing.T) {
	for _, spec := range []string{"timestamp", "=x", "bogus=x", "timestamp="} {
		t.Run(spec, func(t *testing.T) {
			if _, err := ParseColumns(spec); err == nil {
				t.Error("expected an error")
			}
		})
	}
	if columns, err := ParseColumns("  "); err != nil || len(columns) != 0 {
		t.Errorf("empty spec = %v, %v", columns, err)
	}
}

func TestLoadErrors(t *testing.T) {
	tests := []struct {
		name       string
		sourceType string
		data       string
	}{
		{"unknown type", "syslog", "{}"},
		{"empty file", TypeCloudTrail, "  "},
		{"broken json array", TypeGCP, "[{"},
		{"broken json lines", TypeAzure, "{\"a\": 1}\nnot json"},
		{"bad gzip", TypeCloudTrail, "\x1f\x8bnot gzip data"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Load(tt.sourceType, "f", []byte(tt.data), UsageOptions{}); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

func TestEventHelpers(t *testing.T) {
	event := Event{Action: "InvokeModel", Principal: "role/chat", Model: "m", SourceIP: "1.2.3.4"}
	if event.Summary() != "InvokeModel by role/chat on m from 1.2.3.4" {
		t.Errorf("summary = %q", event.Summary())
	}
	if event.Requests() != 1 || (Event{Count: 9}).Requests() != 9 {
		t.Error("Requests gave the wrong answer")
	}
	if _, err := parseTime("2026-03-01T10:00:00Z"); err != nil {
		t.Error(err)
	}
	if parsed, _ := parseTime("2026-03-01 10:00:00"); !parsed.Equal(time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("parsed = %v", parsed)
	}
}
