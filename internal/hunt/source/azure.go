package source

import (
	"encoding/json"
	"fmt"
	"strings"
)

type azureRecord struct {
	OperationName   json.RawMessage `json:"operationName"`
	Caller          string          `json:"caller"`
	EventTimestamp  string          `json:"eventTimestamp"`
	Time            string          `json:"time"`
	ResourceID      string          `json:"resourceId"`
	EventDataID     string          `json:"eventDataId"`
	CorrelationID   string          `json:"correlationId"`
	SubscriptionID  string          `json:"subscriptionId"`
	Status          json.RawMessage `json:"status"`
	CallerIPAddress string          `json:"callerIpAddress"`
	HTTPRequest     struct {
		ClientIPAddress string `json:"clientIpAddress"`
	} `json:"httpRequest"`
}

func azureText(raw json.RawMessage) string {
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		return text
	}
	var object struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(raw, &object); err == nil {
		return object.Value
	}
	return ""
}

func parseAzure(fileName string, data []byte) (Result, error) {
	records, err := jsonRecords(data, "value", "records")
	if err != nil {
		return Result{}, err
	}
	var result Result
	for index, raw := range records {
		var record azureRecord
		if err := json.Unmarshal(raw, &record); err != nil {
			result.Skipped++
			continue
		}
		event, relevant, err := azureEvent(fileName, index, record)
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

func azureEvent(fileName string, index int, record azureRecord) (Event, bool, error) {
	operation := azureText(record.OperationName)
	kind, relevant := classifyAzure(strings.ToLower(operation))
	status := strings.ToLower(azureText(record.Status))
	if !relevant || status == "started" || status == "accepted" {
		return Event{}, false, nil
	}
	timestamp := record.EventTimestamp
	if timestamp == "" {
		timestamp = record.Time
	}
	when, err := parseTime(timestamp)
	if err != nil {
		return Event{}, false, err
	}
	id := record.EventDataID
	if id == "" {
		id = fmt.Sprintf("%s#%d", fileName, index)
	}
	address := record.HTTPRequest.ClientIPAddress
	if address == "" {
		address = record.CallerIPAddress
	}
	return Event{
		ID: id, Time: when, Source: TypeAzure, File: fileName,
		Principal: record.Caller, Account: record.SubscriptionID, Action: operation,
		Service: "azure-openai", SourceIP: address, Kind: kind, Failed: status == "failed",
	}, true, nil
}

func classifyAzure(operation string) (Kind, bool) {
	switch operation {
	case "microsoft.cognitiveservices/accounts/write", "microsoft.cognitiveservices/accounts/deployments/write":
		return KindEnable, true
	case "microsoft.cognitiveservices/accounts/listkeys/action", "microsoft.cognitiveservices/accounts/regeneratekey/action":
		return KindKeyCreate, true
	}
	return KindOther, false
}
