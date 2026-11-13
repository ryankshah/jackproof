package source

import (
	"encoding/json"
	"fmt"
	"strings"
)

type gcpEntry struct {
	InsertID     string `json:"insertId"`
	Timestamp    string `json:"timestamp"`
	ProtoPayload struct {
		MethodName         string `json:"methodName"`
		ServiceName        string `json:"serviceName"`
		ResourceName       string `json:"resourceName"`
		AuthenticationInfo struct {
			PrincipalEmail        string `json:"principalEmail"`
			ServiceAccountKeyName string `json:"serviceAccountKeyName"`
		} `json:"authenticationInfo"`
		RequestMetadata struct {
			CallerIP                string `json:"callerIp"`
			CallerSuppliedUserAgent string `json:"callerSuppliedUserAgent"`
		} `json:"requestMetadata"`
		Status struct {
			Code int `json:"code"`
		} `json:"status"`
		Request  map[string]any `json:"request"`
		Response map[string]any `json:"response"`
	} `json:"protoPayload"`
	Resource struct {
		Labels map[string]string `json:"labels"`
	} `json:"resource"`
}

func parseGCP(fileName string, data []byte) (Result, error) {
	records, err := jsonRecords(data, "entries")
	if err != nil {
		return Result{}, err
	}
	var result Result
	for index, raw := range records {
		var entry gcpEntry
		if err := json.Unmarshal(raw, &entry); err != nil {
			result.Skipped++
			continue
		}
		event, relevant, err := gcpEvent(fileName, index, entry)
		if err != nil {
			result.Skipped++
			continue
		}
		if relevant {
			result.Events = append(result.Events, event)
		}
	}
	SortEvents(result.Events)
	return result, nil
}

func gcpEvent(fileName string, index int, entry gcpEntry) (Event, bool, error) {
	payload := entry.ProtoPayload
	kind, streaming, service, relevant := classifyGCP(entry)
	if !relevant {
		return Event{}, false, nil
	}
	when, err := parseTime(entry.Timestamp)
	if err != nil {
		return Event{}, false, err
	}
	id := entry.InsertID
	if id == "" {
		id = fmt.Sprintf("%s#%d", fileName, index)
	}
	event := Event{
		ID: id, Time: when, Source: TypeGCP, File: fileName,
		Principal: payload.AuthenticationInfo.PrincipalEmail, Account: entry.Resource.Labels["project_id"],
		Action: payload.MethodName, Service: service, SourceIP: payload.RequestMetadata.CallerIP,
		UserAgent: payload.RequestMetadata.CallerSuppliedUserAgent,
		KeyID:     lastSegment(payload.AuthenticationInfo.ServiceAccountKeyName),
		Kind:      kind, Streaming: streaming, Failed: payload.Status.Code != 0,
	}
	if marker := "models/"; strings.Contains(payload.ResourceName, marker) {
		event.Model = payload.ResourceName[strings.LastIndex(payload.ResourceName, marker)+len(marker):]
	}
	if kind == KindKeyCreate {
		if name, ok := payload.Response["name"].(string); ok {
			event.KeyID = lastSegment(name)
		}
	}
	return event, true, nil
}

func classifyGCP(entry gcpEntry) (Kind, bool, string, bool) {
	payload := entry.ProtoPayload
	method := payload.MethodName
	switch payload.ServiceName {
	case "aiplatform.googleapis.com", "generativelanguage.googleapis.com":
		service := "vertex-ai"
		if payload.ServiceName == "generativelanguage.googleapis.com" {
			service = "gemini-api"
		}
		switch {
		case strings.HasSuffix(method, "StreamGenerateContent") || strings.HasSuffix(method, "ServerStreamingPredict") || strings.HasSuffix(method, "StreamRawPredict"):
			return KindInvoke, true, service, true
		case strings.HasSuffix(method, ".Predict") || strings.HasSuffix(method, "GenerateContent") || strings.HasSuffix(method, "RawPredict") || strings.HasSuffix(method, "Embed"):
			return KindInvoke, false, service, true
		case strings.Contains(method, ".List") || strings.Contains(method, ".Get"):
			return KindList, false, service, true
		}
	case "serviceusage.googleapis.com":
		if strings.HasSuffix(method, "EnableService") || strings.HasSuffix(method, "BatchEnableServices") {
			if enablesModelService(entry) {
				return KindEnable, false, "serviceusage", true
			}
		}
	case "iam.googleapis.com":
		if strings.HasSuffix(method, "CreateServiceAccountKey") {
			return KindKeyCreate, false, "iam", true
		}
	}
	return KindOther, false, "", false
}

func enablesModelService(entry gcpEntry) bool {
	candidates := []string{entry.ProtoPayload.ResourceName}
	if ids, ok := entry.ProtoPayload.Request["serviceIds"].([]any); ok {
		for _, id := range ids {
			if text, isText := id.(string); isText {
				candidates = append(candidates, text)
			}
		}
	}
	for _, candidate := range candidates {
		if strings.Contains(candidate, "aiplatform.googleapis.com") || strings.Contains(candidate, "generativelanguage.googleapis.com") {
			return true
		}
	}
	return false
}

func lastSegment(path string) string {
	if index := strings.LastIndex(path, "/"); index >= 0 {
		return path[index+1:]
	}
	return path
}
