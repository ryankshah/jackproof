# Verification record

This file lists the provider documentation behind each `verified: true` flag in the catalogue, checked on 2026-11-14. [unverified.md](unverified.md) lists what is still open.

A flag is set only when the documentation states every fact the entry relies on. A key prefix shown in an example does not confirm a key pattern, because the pattern also asserts a character set and a length.

## Live verification endpoints

Each entry needs the endpoint, the authentication scheme and the status code for a rejected key.

| Provider | Endpoint and authentication | Rejected key |
| --- | --- | --- |
| Anthropic | [List models](https://platform.claude.com/docs/en/api/models/list), [headers](https://platform.claude.com/docs/en/api/overview) | [401](https://platform.claude.com/docs/en/api/errors) |
| OpenAI | [OpenAPI specification](https://github.com/openai/openai-openapi), operation `listModels`, bearer scheme | [401](https://developers.openai.com/api/docs/guides/error-codes) |
| Cohere | [List models](https://docs.cohere.com/v1/reference/list-models), bearer scheme | [401](https://docs.cohere.com/reference/errors) |
| Groq | [API reference](https://console.groq.com/docs/api-reference), bearer scheme | [401](https://console.groq.com/docs/errors) |
| OpenRouter | [Limits](https://openrouter.ai/docs/api-reference/limits), `GET /api/v1/key` | [401](https://openrouter.ai/docs/api-reference/errors) |
| DeepSeek | [List models](https://api-docs.deepseek.com/api/list-models), [base URL and bearer scheme](https://api-docs.deepseek.com/) | [401](https://api-docs.deepseek.com/quick_start/error_codes) |

Anthropic documents `x-api-key` as a legacy fallback that is still supported, and `anthropic-version` value `2023-06-01` on its [versions page](https://platform.claude.com/docs/en/api/versioning).

Not confirmed:
- Google AI Studio: the `key` query parameter and the 400 status for an invalid key are not documented. The documentation shows the `x-goog-api-key` header.
- xAI: a 401 for all endpoints is documented, but the models endpoint is not.
- Mistral: the models endpoint is documented, but a status code for an invalid key is not.
- Together: a 401 for an invalid key is documented, but the models endpoint is not.
- Fireworks: bearer authentication is documented, but the models endpoint and a status code for an invalid key are not.
- Hugging Face: `GET /api/whoami-v2` is documented, but its authentication and the response to an invalid token are not.
- Replicate: `GET /v1/account` and bearer authentication are documented, but a status code for an invalid token is not.

## Key formats

- OpenRouter: [authentication](https://openrouter.ai/docs/api-reference/authentication) states `sk-or-v1-` followed by 64 lowercase hexadecimal characters.
- AWS access key ID: [identifiers](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html) lists the `AKIA` and `ASIA` prefixes.
- Google Cloud service account key: [keys-create-delete](https://cloud.google.com/iam/docs/keys-create-delete) shows the JSON key file with a `private_key` field that holds a PEM block.

The other formats are not documented beyond example strings. Anthropic shows `sk-ant-api03-...` and Hugging Face shows `hf_...`. Replicate shows a masked `r8_` value. OpenAI shows `sk-admin` in its specification. The AWS secret access key is shown only as an example value.

## Cloud roles and managed policies

- AWS: [PowerUserAccess](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/PowerUserAccess.html) allows all actions except `iam:*`, `organizations:*` and `account:*`.
- Google Cloud: [Service Usage roles](https://cloud.google.com/iam/docs/roles-permissions/serviceusage), [Vertex AI roles](https://cloud.google.com/iam/docs/roles-permissions/aiplatform) and [IAM roles](https://cloud.google.com/iam/docs/roles-permissions/iam) list `serviceusage.services.enable`, `aiplatform.endpoints.predict` and `iam.serviceAccountKeys.create` for the roles in the catalogue.
- Azure: [privileged roles](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/privileged) and [AI and machine learning roles](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/ai-machine-learning) list the actions for Owner, Contributor and the three Cognitive Services roles.

The Google Cloud basic roles Owner and Editor are not confirmed, because the documentation does not list their permissions.

## Log event names

- AWS: the [CloudTrail record contents](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html) define `eventName` as an action in the service API. The [Amazon Bedrock API reference](https://docs.aws.amazon.com/bedrock/latest/APIReference/) documents `InvokeModel`, `InvokeModelWithResponseStream`, `Converse`, `ConverseStream`, `ListFoundationModels`, `GetFoundationModel`, `ListInferenceProfiles`, `GetFoundationModelAvailability`, `CreateFoundationModelAgreement` and the three model invocation logging operations. The [IAM API reference](https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateAccessKey.html) documents `CreateAccessKey`.
- Google Cloud: [Service Usage audit logging](https://cloud.google.com/service-usage/docs/audit-logging) lists `EnableService` and `BatchEnableServices`. [IAM audit logging](https://cloud.google.com/iam/docs/audit-logging) lists `CreateServiceAccountKey`.
- Azure: [resource provider operations](https://learn.microsoft.com/en-us/azure/role-based-access-control/permissions/ai-machine-learning) lists the account write, deployment write, `listKeys` and `regenerateKey` operations.

Not confirmed: `PutFoundationModelEntitlement`, the AWS Marketplace `Subscribe` and `AcceptAgreementRequest` events, the Service Quotas service code `bedrock`, and the Vertex AI and Gemini API audit method names. Every hunt rule uses at least one of these, so all hunt rules stay unverified.

## SDK client patterns

The SDK READMEs show these constructors and module paths: OpenAI, Groq, Mistral and Together for Python, and OpenAI, Anthropic, Cohere, Groq and Mistral for JavaScript. The Go modules for OpenAI, Anthropic, Google GenAI, Vertex AI, Amazon Bedrock runtime and `sashabaranov/go-openai` are confirmed, with the `/vN` module suffix handled. Patterns that combine several constructors stay unverified until every alternative is confirmed.
