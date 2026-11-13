# Threat model

LLMjacking is the theft and resale of access to large language models. The attacker does not need to break the model provider. They need a credential, or an identity that can create one, and an account that will pay for the usage.

This page follows the lifecycle of an attack and shows which jackproof rule looks at each stage. A rule marked `unverified` depends on a fact that is not yet confirmed in official documentation. See [unverified.md](unverified.md).

## Lifecycle

| Stage | What the attacker does | Rules | Module |
| --- | --- | --- | --- |
| 1. Find credentials | Reads repositories, container images, CI logs, notebooks and crash reports for provider keys and cloud keys | `JP-KEY-001`, `JP-KEY-040`, `JP-KEY-050` | scan |
| 2. Reach more credentials | Runs code in a workload that holds a key, such as an evaluation runner, a notebook kernel or a pull request job | `JP-KEY-020`, `JP-KEY-021` | scan |
| 3. Widen the blast radius | Uses a key that is shared across environments, or a long-lived cloud key that never expires | `JP-KEY-010`, `JP-KEY-030` | scan |
| 4. Check what the credential can do | Lists models, availability and quotas | `JP-HUNT-006` | hunt |
| 5. Switch on model services | Enables Bedrock, Vertex AI, the Gemini API or Azure OpenAI in an account that never used them | `JP-POS-001`, `JP-POS-002`, `JP-HUNT-001` | posture, hunt |
| 6. Avoid detection | Reads and then deletes the invocation logging configuration | `JP-POS-003`, `JP-HUNT-006` | posture, hunt |
| 7. Persist | Creates a new access key or service account key so access survives rotation of the first credential | `JP-POS-007`, `JP-HUNT-005` | posture, hunt |
| 8. Use and resell | Calls models at volume, often through a proxy gateway that spreads requests across many addresses | `JP-HUNT-002`, `JP-HUNT-003`, `JP-HUNT-004`, `JP-HUNT-007`, `JP-HUNT-008` | hunt |
| 9. Remove the brakes | Relies on a missing budget alert, a missing quota, and wildcard invoke permissions | `JP-POS-004`, `JP-POS-005`, `JP-POS-006` | posture |
| 10. Survive the cleanup | Keeps using a key that someone deleted from a secret store but never revoked | `JP-EXP-001`, `JP-EXP-002`, `JP-EXP-003` | exposure |

## Assumptions

- The attacker already holds a credential or can read one. jackproof does not try to stop the first theft. It reduces what the credential can reach, and it shortens the time before the abuse is noticed.
- Defenders have the repository, the infrastructure code and exported logs. jackproof does not query clouds or providers unless you opt in.
- A provider can tell you which keys were exposed, by name or by fingerprint.

## What jackproof does not cover

- Credentials that never appear in code, infrastructure code or an export you supply, such as keys on a laptop or in a password manager.
- Model abuse that uses a legitimate identity within its normal volume.
- Prompt injection, data leakage through prompts, and the content of model responses.
- Providers and clouds other than those listed in the rule catalogue.
- A guardrail, budget or quota that exists outside the scanned code. These are reported as incomplete, not as absent.

## Why an empty result is not safety

Each module sees only the input it is given. A scan of one repository says nothing about the next one. A log export covers a time range and one source. The coverage section of every report states exactly what was examined, so that an empty result can be read for what it is.
