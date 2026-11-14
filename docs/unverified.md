# Unverified facts

This file is generated from the rule catalogue and the embedded data files. Run `go generate ./...` to update it. Do not edit it by hand.

Each entry below is a provider key format, API field, event name or permission that has not been confirmed against the provider's official documentation. Rules that depend on them carry the `unverified-rule` flag.

## Rules

These rules depend on facts that are not yet confirmed.

- JP-EXP-003: Credential named in an exposure notice still authenticates
- JP-HUNT-001: Model service enabled and then invoked by the same principal
- JP-HUNT-002: Invocation volume or cost far above the principal baseline
- JP-HUNT-003: Principal or account invoked a model it has not used before
- JP-HUNT-004: Model calls from many or unfamiliar source networks
- JP-HUNT-005: Access key created and used from a new source within minutes
- JP-HUNT-006: Reconnaissance before first model use, or logging configuration read then deleted
- JP-HUNT-007: Model invocation by a principal outside the mapped environments
- JP-HUNT-008: Many concurrent streaming requests with uniform parameters
- JP-KEY-001: Literal LLM provider key found in repository
- JP-POS-001: Identity can enable model access where models are not expected
- JP-POS-002: No organization guardrail denies model enablement in non-AI accounts
- JP-POS-003: Model invocation logging is disabled or can be disabled
- JP-POS-004: No budget or billing alert covers model spend
- JP-POS-005: No quota or rate limit is set below the service default
- JP-POS-006: Principal with model invoke permission has wildcard resources
- JP-POS-007: Identity can create long-lived keys for a model-capable principal

## Provider key formats

The patterns that recognise a provider's keys. A wrong pattern causes missed keys or false matches.

- openai, format project-key
- openai, format legacy-key
- anthropic, format api-key
- google-ai-studio, format api-key
- fireworks, format api-key
- together, format api-key
- groq, format api-key
- mistral, format api-key
- cohere, format api-key
- xai, format api-key
- deepseek, format api-key
- huggingface, format access-token
- replicate, format api-token
- perplexity, format api-key
- aws, format secret-access-key
- gcp, format service-account-private-key
- azure-openai, format api-key

## Live verification endpoints

The read-only request that `jackproof exposure verify` sends. The status codes that mean a key was rejected are also unconfirmed.

- openai: GET https://api.openai.com/v1/models with bearer authentication
- anthropic: GET https://api.anthropic.com/v1/models with header:x-api-key authentication
- google-ai-studio: GET https://generativelanguage.googleapis.com/v1beta/models with query:key authentication
- fireworks: GET https://api.fireworks.ai/inference/v1/models with bearer authentication
- together: GET https://api.together.xyz/v1/models with bearer authentication
- groq: GET https://api.groq.com/openai/v1/models with bearer authentication
- mistral: GET https://api.mistral.ai/v1/models with bearer authentication
- cohere: GET https://api.cohere.com/v1/models with bearer authentication
- openrouter: GET https://openrouter.ai/api/v1/key with bearer authentication
- xai: GET https://api.x.ai/v1/models with bearer authentication
- deepseek: GET https://api.deepseek.com/models with bearer authentication
- huggingface: GET https://huggingface.co/api/whoami-v2 with bearer authentication
- replicate: GET https://api.replicate.com/v1/account with bearer authentication

## SDK client patterns

The constructor calls that `scan` treats as use of a provider.

- go code, provider anthropic
- go code, provider aws
- go code, provider cohere
- go code, provider gcp
- go code, provider google-ai-studio
- go code, provider openai
- javascript code, provider anthropic
- javascript code, provider aws
- javascript code, provider cohere
- javascript code, provider google-ai-studio
- javascript code, provider groq
- javascript code, provider huggingface
- javascript code, provider mistral
- javascript code, provider openai
- python code, provider anthropic
- python code, provider aws
- python code, provider azure-openai
- python code, provider cohere
- python code, provider gcp
- python code, provider google-ai-studio
- python code, provider groq
- python code, provider huggingface
- python code, provider mistral
- python code, provider openai
- python code, provider together

## Secret store lookup patterns

The calls that `scan` treats as a read of a named secret. Only a secret whose name identifies an LLM provider becomes a credential in the graph.

- aws-secret lookups
- gcp-secret lookups
- azure-secret lookups
- vault-secret lookups

## Cloud permissions and roles

The action names, permissions and managed roles that `posture` uses to decide what an identity can do.

- managed-policy:arn:aws:iam::aws:policy/PowerUserAccess
- gcp-role:roles/owner
- gcp-role:roles/editor
- gcp-role:roles/serviceusage.serviceUsageAdmin
- gcp-role:roles/aiplatform.admin
- gcp-role:roles/aiplatform.user
- gcp-role:roles/iam.serviceAccountKeyAdmin
- azure-role:Owner
- azure-role:Contributor
- azure-role:Cognitive Services Contributor
- azure-role:Cognitive Services OpenAI Contributor
- azure-role:Cognitive Services OpenAI User

## Log event and field names

The names that `hunt` reads from exported logs.

- azure activity log: Microsoft.CognitiveServices/accounts write, deployments write, listKeys and regenerateKey operations
- cloudtrail: aws-marketplace.amazonaws.com AcceptAgreementRequest
- cloudtrail: aws-marketplace.amazonaws.com Subscribe
- cloudtrail: bedrock.amazonaws.com Converse
- cloudtrail: bedrock.amazonaws.com ConverseStream
- cloudtrail: bedrock.amazonaws.com CreateFoundationModelAgreement
- cloudtrail: bedrock.amazonaws.com DeleteModelInvocationLoggingConfiguration
- cloudtrail: bedrock.amazonaws.com GetFoundationModel
- cloudtrail: bedrock.amazonaws.com GetFoundationModelAvailability
- cloudtrail: bedrock.amazonaws.com GetModelInvocationLoggingConfiguration
- cloudtrail: bedrock.amazonaws.com InvokeModel
- cloudtrail: bedrock.amazonaws.com InvokeModelWithResponseStream
- cloudtrail: bedrock.amazonaws.com ListFoundationModels
- cloudtrail: bedrock.amazonaws.com ListInferenceProfiles
- cloudtrail: bedrock.amazonaws.com PutFoundationModelEntitlement
- cloudtrail: bedrock.amazonaws.com PutModelInvocationLoggingConfiguration
- cloudtrail: iam.amazonaws.com CreateAccessKey
- cloudtrail: servicequotas.amazonaws.com requests for service code bedrock
- gcp audit: aiplatform.googleapis.com and generativelanguage.googleapis.com prediction and listing methods
- gcp audit: iam.googleapis.com CreateServiceAccountKey
- gcp audit: serviceusage.googleapis.com EnableService and BatchEnableServices

## Heuristics

These are judgements, not provider facts. They affect confidence and are flagged as inferred in findings.

- Workload names and images that suggest untrusted code: eval, sandbox, jupyter, notebook, runner, plugin, playground, executor, interpreter.
- Environment variable names that suggest a telemetry or crash reporting sink: SENTRY_DSN, DD_API_KEY, NEW_RELIC_LICENSE_KEY, OTEL_EXPORTER_OTLP_ENDPOINT, HONEYCOMB_API_KEY, BUGSNAG_API_KEY, ROLLBAR_ACCESS_TOKEN.
- GitHub Actions inputs that carry cloud credentials: aws-access-key-id, aws-secret-access-key, credentials_json.
- Model name patterns treated as high cost by default: *opus*, *gpt-4*, *o1*, *ultra*.
- The default thresholds of the hunt detections. They are configurable in jackproof.yaml.
- The Sigma rules written by `hunt export-sigma`. They have not been run against a live SIEM.
