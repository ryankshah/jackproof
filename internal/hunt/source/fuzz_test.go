package source

import "testing"

func FuzzLoad(f *testing.F) {
	f.Add(uint8(0), []byte(`{"Records":[{"eventTime":"2026-03-01T10:00:00Z","eventSource":"bedrock.amazonaws.com","eventName":"InvokeModel","userIdentity":{"arn":"a"}}]}`))
	f.Add(uint8(1), []byte(`[{"insertId":"1","timestamp":"2026-03-01T10:00:00Z","protoPayload":{"serviceName":"aiplatform.googleapis.com","methodName":"x.Predict"}}]`))
	f.Add(uint8(2), []byte(`{"value":[{"operationName":{"value":"Microsoft.CognitiveServices/accounts/write"},"eventTimestamp":"2026-03-01T10:00:00Z","status":"Succeeded"}]}`))
	f.Add(uint8(3), []byte("timestamp,principal,requests,cost\n2026-03-01T10:00:00Z,k,5,$1.5\n"))
	f.Add(uint8(0), []byte("\x1f\x8b\x08"))
	f.Add(uint8(1), []byte("{\"a\":1}\n{\"b\":"))
	f.Fuzz(func(t *testing.T, kind uint8, data []byte) {
		result, err := Load(Types[int(kind)%len(Types)], "fuzz", data, UsageOptions{})
		if err != nil {
			return
		}
		for _, event := range result.Events {
			if event.Time.IsZero() {
				t.Fatalf("an event has no time: %+v", event)
			}
			if event.Requests() < 1 {
				t.Fatalf("an event counts %d requests", event.Requests())
			}
		}
		for i := 1; i < len(result.Events); i++ {
			if result.Events[i].Time.Before(result.Events[i-1].Time) {
				t.Fatal("events are not sorted by time")
			}
		}
	})
}

func FuzzParseColumns(f *testing.F) {
	f.Add("timestamp=ts,principal=key")
	f.Add("")
	f.Add("=,=,")
	f.Fuzz(func(t *testing.T, spec string) {
		_, _ = ParseColumns(spec)
	})
}
