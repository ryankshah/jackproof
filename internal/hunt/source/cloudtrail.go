package source

import (
	"encoding/json"
	"fmt"
	"strings"
)

type cloudTrailRecord struct {
	EventTime    string `json:"eventTime"`
	EventSource  string `json:"eventSource"`
	EventName    string `json:"eventName"`
	AWSRegion    string `json:"awsRegion"`
	SourceIP     string `json:"sourceIPAddress"`
	UserAgent    string `json:"userAgent"`
	ErrorCode    string `json:"errorCode"`
	EventID      string `json:"eventID"`
	RecipientAcc string `json:"recipientAccountId"`
	UserIdentity struct {
		ARN            string `json:"arn"`
		AccountID      string `json:"accountId"`
		AccessKeyID    string `json:"accessKeyId"`
		SessionContext struct {
			SessionIssuer struct {
				ARN string `json:"arn"`
			} `json:"sessionIssuer"`
		} `json:"sessionContext"`
	} `json:"userIdentity"`
	RequestParameters map[string]any `json:"requestParameters"`
	ResponseElements  map[string]any `json:"responseElements"`
}

var bedrockKinds = map[string]struct {
	kind      Kind
	streaming bool
}{
	"InvokeModel":                               {KindInvoke, false},
	"Converse":                                  {KindInvoke, false},
	"InvokeModelWithResponseStream":             {KindInvoke, true},
	"ConverseStream":                            {KindInvoke, true},
	"ListFoundationModels":                      {KindList, false},
	"GetFoundationModel":                        {KindList, false},
	"ListInferenceProfiles":                     {KindList, false},
	"GetFoundationModelAvailability":            {KindList, false},
	"PutFoundationModelEntitlement":             {KindEnable, false},
	"CreateFoundationModelAgreement":            {KindEnable, false},
	"GetModelInvocationLoggingConfiguration":    {KindLoggingRead, false},
	"DeleteModelInvocationLoggingConfiguration": {KindLoggingDelete, false},
	"PutModelInvocationLoggingConfiguration":    {KindLoggingWrite, false},
}

func parseCloudTrail(fileName string, data []byte) (Result, error) {
	records, err := jsonRecords(data, "Records")
	if err != nil {
		return Result{}, err
	}
	var result Result
	for index, raw := range records {
		var record cloudTrailRecord
		if err := json.Unmarshal(raw, &record); err != nil {
			result.Skipped++
			continue
		}
		event, relevant, err := cloudTrailEvent(fileName, index, record)
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

func cloudTrailEvent(fileName string, index int, record cloudTrailRecord) (Event, bool, error) {
	kind, streaming, service, relevant := classifyCloudTrail(record)
	if !relevant {
		return Event{}, false, nil
	}
	when, err := parseTime(record.EventTime)
	if err != nil {
		return Event{}, false, err
	}
	principal := record.UserIdentity.ARN
	if issuer := record.UserIdentity.SessionContext.SessionIssuer.ARN; issuer != "" {
		principal = issuer
	}
	account := record.UserIdentity.AccountID
	if record.RecipientAcc != "" {
		account = record.RecipientAcc
	}
	id := record.EventID
	if id == "" {
		id = fmt.Sprintf("%s#%d", fileName, index)
	}
	event := Event{
		ID: id, Time: when, Source: TypeCloudTrail, File: fileName,
		Principal: principal, Account: account, Region: record.AWSRegion,
		Action: record.EventName, Service: service, SourceIP: record.SourceIP, UserAgent: record.UserAgent,
		KeyID: record.UserIdentity.AccessKeyID, Kind: kind, Streaming: streaming, Failed: record.ErrorCode != "",
	}
	if model, ok := record.RequestParameters["modelId"].(string); ok {
		event.Model = trimModelARN(model)
	}
	if kind == KindKeyCreate {
		event.KeyID = createdAccessKey(record.ResponseElements)
	}
	return event, true, nil
}

func classifyCloudTrail(record cloudTrailRecord) (Kind, bool, string, bool) {
	switch record.EventSource {
	case "bedrock.amazonaws.com":
		if entry, ok := bedrockKinds[record.EventName]; ok {
			return entry.kind, entry.streaming, "bedrock", true
		}
	case "aws-marketplace.amazonaws.com":
		if record.EventName == "Subscribe" || record.EventName == "AcceptAgreementRequest" {
			return KindEnable, false, "bedrock", true
		}
	case "servicequotas.amazonaws.com":
		if code, ok := record.RequestParameters["serviceCode"].(string); ok && strings.EqualFold(code, "bedrock") {
			return KindList, false, "bedrock", true
		}
	case "iam.amazonaws.com":
		if record.EventName == "CreateAccessKey" {
			return KindKeyCreate, false, "iam", true
		}
	}
	return KindOther, false, "", false
}

func createdAccessKey(response map[string]any) string {
	if accessKey, ok := response["accessKey"].(map[string]any); ok {
		if id, ok := accessKey["accessKeyId"].(string); ok {
			return id
		}
	}
	return ""
}

func trimModelARN(model string) string {
	for _, marker := range []string{"foundation-model/", "inference-profile/"} {
		if index := strings.LastIndex(model, marker); index >= 0 {
			return model[index+len(marker):]
		}
	}
	return model
}
