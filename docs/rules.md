# Rules

This file is generated from the rule catalogue and the embedded data files. Run `go generate ./...` to update it. Do not edit it by hand.

| Rule | Module | Severity | Verified | Title |
| --- | --- | --- | --- | --- |
| [JP-EXP-001](#jp-exp-001) | exposure | high | yes | Credential named in an exposure notice is defined or used here |
| [JP-EXP-002](#jp-exp-002) | exposure | medium | yes | Credential named in an exposure notice was not found in the scanned paths |
| [JP-EXP-003](#jp-exp-003) | exposure | critical | no | Credential named in an exposure notice still authenticates |
| [JP-HUNT-001](#jp-hunt-001) | hunt | high | no | Model service enabled and then invoked by the same principal |
| [JP-HUNT-002](#jp-hunt-002) | hunt | medium | no | Invocation volume or cost far above the principal baseline |
| [JP-HUNT-003](#jp-hunt-003) | hunt | medium | no | Principal or account invoked a model it has not used before |
| [JP-HUNT-004](#jp-hunt-004) | hunt | high | no | Model calls from many or unfamiliar source networks |
| [JP-HUNT-005](#jp-hunt-005) | hunt | high | no | Access key created and used from a new source within minutes |
| [JP-HUNT-006](#jp-hunt-006) | hunt | medium | no | Reconnaissance before first model use, or logging configuration read then deleted |
| [JP-HUNT-007](#jp-hunt-007) | hunt | medium | no | Model invocation by a principal outside the mapped environments |
| [JP-HUNT-008](#jp-hunt-008) | hunt | high | no | Many concurrent streaming requests with uniform parameters |
| [JP-KEY-001](#jp-key-001) | scan | high | no | Literal LLM provider key found in repository |
| [JP-KEY-010](#jp-key-010) | scan | high | yes | Same credential used across environments |
| [JP-KEY-020](#jp-key-020) | scan | high | yes | Credential exposed to a workload that runs untrusted code |
| [JP-KEY-021](#jp-key-021) | scan | medium | yes | Credential passed as a plain environment variable to a job with a shared log or telemetry sink |
| [JP-KEY-030](#jp-key-030) | scan | high | yes | Long-lived cloud key used where short-lived or federated credentials are available |
| [JP-KEY-040](#jp-key-040) | scan | high | yes | Credential reaches a logger, error message or HTTP response |
| [JP-KEY-050](#jp-key-050) | scan | high | yes | Credential stored in a container image layer |
| [JP-POS-001](#jp-pos-001) | posture | high | no | Identity can enable model access where models are not expected |
| [JP-POS-002](#jp-pos-002) | posture | medium | no | No organization guardrail denies model enablement in non-AI accounts |
| [JP-POS-003](#jp-pos-003) | posture | high | no | Model invocation logging is disabled or can be disabled |
| [JP-POS-004](#jp-pos-004) | posture | medium | no | No budget or billing alert covers model spend |
| [JP-POS-005](#jp-pos-005) | posture | low | no | No quota or rate limit is set below the service default |
| [JP-POS-006](#jp-pos-006) | posture | medium | no | Principal with model invoke permission has wildcard resources |
| [JP-POS-007](#jp-pos-007) | posture | high | no | Identity can create long-lived keys for a model-capable principal |

## JP-EXP-001

Credential named in an exposure notice is defined or used here

- Module: exposure
- Severity: high
- Verified against provider documentation: yes
- Matcher: `exposed-credential-location`

A fingerprint, secret name or key supplied from an exposure notice matches a credential that this code defines, references or injects into a workload. Each listed location needs the replacement credential, and the old credential stays valid until the provider revokes it.

Fix: Follow the rotation plan. Create the replacement first, update every listed location, restart the workloads in the listed order, then revoke the old credential at the provider.

References:

- https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html

## JP-EXP-002

Credential named in an exposure notice was not found in the scanned paths

- Module: exposure
- Severity: medium
- Verified against provider documentation: yes
- Matcher: `exposed-credential-not-found`

A fingerprint, secret name or key supplied from an exposure notice did not match anything in the scanned paths. This does not show that the credential is unused. Other repositories, CI settings, secret managers, developer machines and deployed systems can still hold it.

Fix: Search the other places that can hold the credential. Revoke it at the provider even when no use is found, because a credential named in an exposure notice is exposed.

References:

- https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html

## JP-EXP-003

Credential named in an exposure notice still authenticates

- Module: exposure
- Severity: critical
- Verified against provider documentation: no
- Matcher: `exposed-credential-live`

A read-only metadata request to the provider succeeded with the credential. The credential has not been revoked, so anyone who holds it can use the account.

Fix: Revoke the credential at the provider now. Deleting it from a secret store, CI setting or file does not revoke it.

References:

- https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html

## JP-HUNT-001

Model service enabled and then invoked by the same principal

- Module: hunt
- Severity: high
- Verified against provider documentation: no
- Matcher: `enable-then-invoke`

A principal enabled a model service or requested model access, and the same principal invoked a model shortly afterwards. This is the usual first step of LLMjacking in an account that never used models. The attacker switches the service on, then runs it at the owner's expense.

Fix: Confirm with the principal's owner that the enablement was planned. If it was not, disable the credential, remove the model access, and review every action the principal took in the window.

References:

- https://docs.aws.amazon.com/bedrock/latest/userguide/logging-using-cloudtrail.html
- https://cloud.google.com/vertex-ai/docs/general/audit-logging
- https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log

## JP-HUNT-002

Invocation volume or cost far above the principal baseline

- Module: hunt
- Severity: medium
- Verified against provider documentation: no
- Matcher: `volume-spike`

A principal invoked models many times more often than its own rolling median, or spent many times more than usual in one period. Stolen access is often resold, so volume rises sharply once a proxy starts using it.

Fix: Check whether the workload that owns this principal changed. If not, rotate the credential, review the callers, and set a quota or budget that would have stopped the spike.

References:

- https://docs.aws.amazon.com/bedrock/latest/userguide/logging-using-cloudtrail.html
- https://cloud.google.com/vertex-ai/docs/general/audit-logging

## JP-HUNT-003

Principal or account invoked a model it has not used before

- Module: hunt
- Severity: medium
- Verified against provider documentation: no
- Matcher: `first-seen-model`

A principal that had a history of invocations called a model that neither it nor its account had called before. Attackers favour the most capable and most expensive models, so a new high-cost model is a sign of misuse.

Fix: Confirm with the owner that the model change was planned. If it was not, review the principal's other activity, and restrict the principal to the models its workload needs.

References:

- https://docs.aws.amazon.com/bedrock/latest/userguide/logging-using-cloudtrail.html
- https://cloud.google.com/vertex-ai/docs/general/audit-logging

## JP-HUNT-004

Model calls from many or unfamiliar source networks

- Module: hunt
- Severity: high
- Verified against provider documentation: no
- Matcher: `source-network`

A principal called models from many distinct addresses in a short time, from a network it never used before, or from a hosting provider when its history shows only corporate egress. Proxy gateways that resell stolen access spread calls across many addresses.

Fix: Compare the addresses with your egress ranges. Rotate the credential if they are not yours, and restrict it to known networks where the platform allows source conditions.

References:

- https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html
- https://cloud.google.com/vertex-ai/docs/general/audit-logging

## JP-HUNT-005

Access key created and used from a new source within minutes

- Module: hunt
- Severity: high
- Verified against provider documentation: no
- Matcher: `key-created-then-used`

An access key or service account key was created, and the new key was used from a different address within a short window. A key that is created and immediately used elsewhere has usually been taken by someone other than the creator.

Fix: Delete the key, then review the principal that created it. Treat the principal as compromised until the creation is explained.

References:

- https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html
- https://cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys

## JP-HUNT-006

Reconnaissance before first model use, or logging configuration read then deleted

- Module: hunt
- Severity: medium
- Verified against provider documentation: no
- Matcher: `reconnaissance`

A principal listed models or checked availability and quotas shortly before its first invocation, or read the invocation logging configuration and then deleted it. Both patterns appear when an attacker maps what a stolen identity can do and then removes the evidence.

Fix: Review everything the principal did in the window. Restore the logging configuration, and confirm that the principal's owner made the changes.

References:

- https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html
- https://docs.aws.amazon.com/bedrock/latest/userguide/logging-using-cloudtrail.html

## JP-HUNT-007

Model invocation by a principal outside the mapped environments

- Module: hunt
- Severity: medium
- Verified against provider documentation: no
- Matcher: `unmapped-principal`

A principal invoked models from an account that jackproof.yaml does not list as owned, or invoked a provider that no scanned code uses. Legitimate workloads appear in the code and the account list. An invocation with no matching code or account is unexplained.

Fix: Identify the owner of the principal. If no workload accounts for it, disable the credential. If a workload does, add its account to owned_accounts or scan the repository that contains it.

References:

- https://docs.aws.amazon.com/bedrock/latest/userguide/logging-using-cloudtrail.html

## JP-HUNT-008

Many concurrent streaming requests with uniform parameters

- Module: hunt
- Severity: high
- Verified against provider documentation: no
- Matcher: `streaming-burst`

A principal sent a large number of streaming model requests in a short window, and nearly all used the same model and client. Reseller gateways relay many users through one credential and produce this pattern.

Fix: Rotate the credential, then set a rate limit or quota that matches the real workload. Review who holds the credential.

References:

- https://docs.aws.amazon.com/bedrock/latest/userguide/logging-using-cloudtrail.html

## JP-KEY-001

Literal LLM provider key found in repository

- Module: scan
- Severity: high
- Verified against provider documentation: no
- Matcher: `provider-key-literal`

A string in a file of the scanned tree matches the key format of an LLM provider or a cloud credential that can reach model services. Where git tracks the file, anyone with read access to the repository, its forks or its history can use the key. Where git ignores the file, the key is on this machine only, and the finding is low severity.

Fix: Revoke the key at the provider, create a replacement, store it in a secret manager and inject it at runtime. Removing the line from the file does not remove it from git history.

References:

- https://docs.github.com/en/code-security/secret-scanning/introduction/about-secret-scanning

## JP-KEY-010

Same credential used across environments

- Module: scan
- Severity: high
- Verified against provider documentation: yes
- Matcher: `cross-environment-credential`

One key or secret reference is delivered to workloads in more than one environment. A compromise of the least protected environment exposes every other environment that shares the credential, and one stolen key carries the spend of all of them.

Fix: Issue a separate credential for each environment. Set a spend limit on each at the provider. Rotate the shared credential after the split.

References:

- https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html

## JP-KEY-020

Credential exposed to a workload that runs untrusted code

- Module: scan
- Severity: high
- Verified against provider documentation: yes
- Matcher: `credential-in-untrusted-workload`

A credential is available to a workload that runs untrusted or user-supplied code, such as an evaluation runner, notebook kernel, sandbox, plugin host, or a CI job triggered by pull_request_target. Code in that workload can read the credential and send it elsewhere.

Fix: Remove the credential from the workload. Route model calls through a proxy that holds the key and enforces per-caller limits. For pull_request_target jobs, do not check out or run pull request code in a job that has secrets.

References:

- https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions
- https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/

## JP-KEY-021

Credential passed as a plain environment variable to a job with a shared log or telemetry sink

- Module: scan
- Severity: medium
- Verified against provider documentation: yes
- Matcher: `credential-env-with-shared-sink`

A credential is placed in the process environment of a workload whose output or diagnostics leave the workload. Environment dumps, debug output and crash reports can carry the value to CI logs or a third-party service.

Fix: Pass the credential through a mechanism that does not put it in the process environment, such as a mounted secret file or a secret-manager call at the point of use. Remove environment dumps and debug tracing from jobs that hold credentials.

References:

- https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
- https://docs.github.com/en/actions/security-for-github-actions/security-guides/using-secrets-in-github-actions

## JP-KEY-030

Long-lived cloud key used where short-lived or federated credentials are available

- Module: scan
- Severity: high
- Verified against provider documentation: yes
- Matcher: `static-cloud-key`

A static access key or service account key is delivered to a workload on a platform that can issue short-lived credentials, such as GitHub Actions OIDC, IAM roles for service accounts, or workload identity federation. A static key stays valid until someone revokes it, so a stolen copy keeps working.

Fix: Replace the static key with a role or federated identity bound to the workload. Delete the static key after the workload is switched over.

References:

- https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect
- https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html
- https://cloud.google.com/iam/docs/workload-identity-federation

## JP-KEY-040

Credential reaches a logger, error message or HTTP response

- Module: scan
- Severity: high
- Verified against provider documentation: yes
- Matcher: `credential-to-sink`

Code reads a credential and passes it to a logging call, an error constructor, a panic or a response writer. Logs and error reports are widely readable and are often forwarded to third parties.

Fix: Remove the value from the call. If the call needs to identify the key, log the fingerprint or the last four characters instead.

References:

- https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
- https://cwe.mitre.org/data/definitions/532.html

## JP-KEY-050

Credential stored in a container image layer

- Module: scan
- Severity: high
- Verified against provider documentation: yes
- Matcher: `credential-in-image`

A Dockerfile sets a credential with ENV or ARG, or copies a dotenv file into the image. Anyone who can pull the image can read the value from its layers or its build history.

Fix: Remove the credential from the Dockerfile. Pass it at run time, or use a build secret mount for build-time needs. Rebuild the image and revoke the exposed credential.

References:

- https://docs.docker.com/build/building/secrets/

## JP-POS-001

Identity can enable model access where models are not expected

- Module: posture
- Severity: high
- Verified against provider documentation: no
- Matcher: `enable-model-access`

A policy lets an identity subscribe to or enable a model service in an account, project or subscription that jackproof.yaml does not list as an expected model environment. An attacker with that identity can switch on Bedrock, Vertex AI, the Gemini API or Azure OpenAI in an account that never used them, and run models at the owner's expense.

Fix: Remove the enabling actions from the identity, or add the service to expected_providers for this environment in jackproof.yaml if models are intended there. Deny model enablement with an organization guardrail in accounts that do not need it.

References:

- https://docs.aws.amazon.com/bedrock/latest/userguide/model-access.html
- https://cloud.google.com/service-usage/docs/enable-disable
- https://learn.microsoft.com/en-us/azure/ai-services/openai/how-to/create-resource

## JP-POS-002

No organization guardrail denies model enablement in non-AI accounts

- Module: posture
- Severity: medium
- Verified against provider documentation: no
- Matcher: `missing-guardrail`

The scanned infrastructure code defines cloud resources but no service control policy, organization policy or Azure Policy that denies model services. Without a guardrail, any identity with enough permissions in a non-AI account can enable and use models there.

Fix: Add an organization-level guardrail that denies the model services in accounts that do not need them. Guardrails often live outside the repository that holds workload code, so confirm where they are defined before treating this as a gap.

References:

- https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html
- https://cloud.google.com/resource-manager/docs/organization-policy/overview
- https://learn.microsoft.com/en-us/azure/governance/policy/overview

## JP-POS-003

Model invocation logging is disabled or can be disabled

- Module: posture
- Severity: high
- Verified against provider documentation: no
- Matcher: `invocation-logging`

Model invocation logging is not configured, is configured with delivery turned off, or can be switched off by an identity that is not an administrator. Without invocation records, stolen access leaves little evidence of who called which model and when.

Fix: Turn on invocation logging with delivery to a log destination that the model-using identities cannot modify. Remove the permission to change the logging configuration from non-administrator identities.

References:

- https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html
- https://cloud.google.com/logging/docs/audit/configure-data-access
- https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/diagnostic-settings

## JP-POS-004

No budget or billing alert covers model spend

- Module: posture
- Severity: medium
- Verified against provider documentation: no
- Matcher: `missing-budget`

Models are enabled or used in this cloud account, and no budget or billing alert in the scanned code covers model spend. Stolen model access has produced charges of six figures in a day, and a budget alert is often the first sign.

Fix: Create a budget with an alert threshold that covers the model service, and send the alert to a channel that someone watches. Budgets can be defined outside this repository, so confirm before adding a duplicate.

References:

- https://docs.aws.amazon.com/cost-management/latest/userguide/budgets-managing-costs.html
- https://cloud.google.com/billing/docs/how-to/budgets
- https://learn.microsoft.com/en-us/azure/cost-management-billing/costs/tutorial-acm-create-budgets

## JP-POS-005

No quota or rate limit is set below the service default

- Module: posture
- Severity: low
- Verified against provider documentation: no
- Matcher: `missing-quota`

Models are enabled or used in this cloud account, and the scanned code sets no quota or rate limit for the model service. The default limits are sized for production use, so an attacker can run at a high rate before anything throttles them.

Fix: Lower the quota or deployment capacity to the level the workload needs. The default for the service is not known to jackproof, so the value you set must be checked against it.

References:

- https://docs.aws.amazon.com/servicequotas/latest/userguide/intro.html
- https://cloud.google.com/docs/quotas/overview
- https://learn.microsoft.com/en-us/azure/ai-services/openai/quotas-limits

## JP-POS-006

Principal with model invoke permission has wildcard resources

- Module: posture
- Severity: medium
- Verified against provider documentation: no
- Matcher: `wildcard-invoke`

An identity can invoke models through a wildcard action or on every resource. If the identity is compromised, the attacker can call every model in the account, including the most expensive ones.

Fix: Limit the invoke permission to the specific models and regions the workload uses. Replace wildcard actions with the individual invoke actions.

References:

- https://docs.aws.amazon.com/bedrock/latest/userguide/security_iam_id-based-policy-examples.html
- https://cloud.google.com/vertex-ai/docs/general/access-control
- https://learn.microsoft.com/en-us/azure/ai-services/openai/how-to/role-based-access-control

## JP-POS-007

Identity can create long-lived keys for a model-capable principal

- Module: posture
- Severity: high
- Verified against provider documentation: no
- Matcher: `credential-creation`

An identity can create access keys or service account keys for a principal that can invoke models. A key created this way works from anywhere and stays valid until someone deletes it, so one compromised identity becomes durable model access.

Fix: Remove the key creation permission from this identity, or restrict it to principals that cannot invoke models. Prefer roles and workload identity over long-lived keys for model-capable principals.

References:

- https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html
- https://cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys
