# jackproof

![ci](https://github.com/ryankshah/jackproof/actions/workflows/ci.yml/badge.svg) ![license](https://img.shields.io/badge/license-Apache--2.0-blue)

jackproof finds, scores, detects and responds to LLMjacking risk: the theft and resale of LLM access through stolen API keys, cloud credentials and model-service permissions. It is a single static Go binary. All analysis is offline unless you pass an explicit opt-in flag.

## The problem

Attackers steal LLM credentials and cloud identities, switch on model services the victim never used, and resell the access through proxy gateways. Charges can reach six figures in a day. Most teams do not know where their LLM credentials live, which workloads can read them, or whether an identity can enable a model service in an account that never used one. When a provider reports an exposed key, teams struggle to find every place it is used, rotate it in a safe order, and prove that the old key is dead.

## Install

```
go install github.com/ryankshah/jackproof/cmd/jackproof@latest
```

To build from a checkout, run `make build` (Go 1.26 or newer), or `scripts/build.ps1` on Windows. The Dockerfile builds a distroless, non-root image:

```
docker build -t jackproof .
docker run --rm --read-only -v "$PWD:/work:ro" jackproof scan .
```

The image has no git, so `diff` and `scan --staged` need the binary on the host.

## Modules

| Command | Question it answers |
| --- | --- |
| `scan` | Where are the LLM credentials, and which workloads can read them |
| `posture` | Can an attacker turn on and abuse model services |
| `hunt` | Is it happening right now |
| `exposure` | A provider says a key leaked. What do I rotate, in what order |

Every finding carries its evidence, the method that produced it, a confidence level, and a list of what the tool could not establish. See [docs/evidence-model.md](docs/evidence-model.md).

## Quickstart: scan

`scan` reads a repository, finds literal keys and references to them, and builds a graph of the workloads that hold each credential. The key below is built at run time and is not a real key.

```
mkdir demo && cd demo
KEY="sk-ant-$(printf 'x%.0s' $(seq 1 90))"
printf 'ANTHROPIC_API_KEY=%s\n' "$KEY" > .env
jackproof scan .
```

```
jackproof scan: 1 finding: 1 high

HIGH     JP-KEY-001  Anthropic key sk-a...xxxx found in .env  [high confidence]
         .env:1
           ANTHROPIC_API_KEY=sk-a...xxxx
         flags: unverified-rule
         not established: Whether the key is still active.
         fix: Revoke the key at the provider, create a replacement, store it in a secret manager and inject it at runtime. Removing the line from the file does not remove it from git history.
         id: ed688e864c41

Credential graph
  Anthropic sk-a...xxxx (literal key)
    defined at .env:1
    if a holder is compromised: Model inference billed to the Anthropic workspace or organization that owns the key.

Coverage
  files scanned: 1 (dotenv 1)
  rules not verified against provider documentation: JP-KEY-001
  not verified against provider documentation: 17 provider key formats, 25 SDK client patterns
```

Add a Compose file, Kubernetes manifest, GitHub Actions workflow, Dockerfile or Terraform and the graph also lists each holder, its environment and whether it may run untrusted code.

## Quickstart: posture

`posture` reads Terraform and reports identities that can enable or abuse Bedrock, Vertex AI, the Gemini API or Azure OpenAI. Tell it where models are expected with `expected_providers` in [jackproof.yaml](docs/configuration.md).

```
cat > main.tf <<'EOF'
resource "aws_iam_role" "deployer" { name = "deployer" }

resource "aws_iam_role_policy" "deployer" {
  role   = aws_iam_role.deployer.id
  policy = jsonencode({ Statement = [{ Effect = "Allow", Action = ["aws-marketplace:Subscribe"], Resource = "*" }] })
}
EOF
jackproof posture .
```

```
jackproof posture: 2 findings: 1 high, 1 medium

HIGH     JP-POS-001  deployer can enable Amazon Bedrock  [medium confidence]
         main.tf:3
           resource "aws_iam_role_policy" "deployer" {
         main.tf:5
           policy = jsonencode({ Statement = [{ Effect = "Allow", Action = ["aws-marketplace:Subscribe"], Resource = "*" }] })
         flags: unverified-rule
         not established: jackproof.yaml has no expected_providers entry for this environment, so it is not known whether models are expected here.
         not established: The matched permission is not specific to model services: aws-marketplace:Subscribe.
         fix: Remove the enabling actions from the identity, or add the service to expected_providers for this environment in jackproof.yaml if models are intended there. Deny model enablement with an organization guardrail in accounts that do not need it.
         id: bd675e31c40d

MEDIUM   JP-POS-002  No AWS guardrail denies model services in the scanned infrastructure code  [medium confidence]
         main.tf:1
           resource "aws_iam_role" "deployer" { name = "deployer" }
         flags: unverified-rule, incomplete
         not established: Whether a guardrail is defined outside the scanned paths, for example in the organization management account.
         fix: Add an organization-level guardrail that denies the model services in accounts that do not need them. Guardrails often live outside the repository that holds workload code, so confirm where they are defined before treating this as a gap.
         id: e61cb6e8d383

Coverage
  files scanned: 1 (terraform 1)
  rules not verified against provider documentation: JP-POS-001, JP-POS-002, JP-POS-003, JP-POS-004, JP-POS-005, JP-POS-006, JP-POS-007
  not verified against provider documentation: 12 cloud permission entries
```

Each finding ships a ready-to-apply snippet in the `md`, `json` and `html` formats and in `jackproof explain`: a service control policy, an organization policy, a budget block or a logging configuration.

## Quickstart: exposure

`exposure` takes fingerprints, secret names or raw keys from an exposure notice. It lists every place the credential is defined, referenced or injected, and writes a rotation plan. Raw keys are hashed in memory and never stored.

```
mkdir exposed && cd exposed
printf 'ANTHROPIC_API_KEY=%s\n' "$KEY" > .env
printf '%s\n' "$KEY" | jackproof exposure --keys-stdin --format text .
```

```
jackproof exposure: 1 finding: 1 high

HIGH     JP-EXP-001  Fingerprint c54130ca536b2344 (sha256) appears in 1 location  [high confidence]
         .env:1
           ANTHROPIC_API_KEY=sk-a...xxxx
         not established: Whether the credential is also held outside the scanned paths.
         fix: Follow the rotation plan. Create the replacement first, update every listed location, restart the workloads in the listed order, then revoke the old credential at the provider.
         id: 7bf60c742e47

Rotation plan
Deleting a stored secret does not revoke it. The old credential stays valid until the provider revokes it.

### Fingerprint c54130ca536b2344 (sha256)

Blast radius: 0 workloads, 0 environments.
If it is abused: Model inference billed to the Anthropic workspace or organization that owns the key.

1. **Create.** Create one replacement anthropic credential before changing anything that uses the old one.
2. **Update.** Replace the stored value at each location. Update CI settings, secret managers and platform secrets before the files that deploy from them.
   - `.env:1`: definition
3. **Verify.** Confirm that each workload authenticates with the replacement credential. Check the provider usage log for requests that still use the old credential.
4. **Revoke.** Revoke the old credential at the provider once no workload uses it. Deleting a stored secret does not revoke it. The old credential stays valid until the provider revokes it.
5. **Cleanup.** Remove the literal value from version control history and treat every fork and clone as exposed. Removing the line from the current files does not remove it from history.


Coverage
  files scanned: 1 (dotenv 1)
  rules not verified against provider documentation: JP-KEY-001
  not verified against provider documentation: 17 provider key formats, 25 SDK client patterns
```

To check that the old key is dead, run `jackproof exposure verify --keys-stdin --verify-live --i-own-these-keys`. It sends one read-only metadata request per key and never calls a model. A rejected result is the only proof that a key is dead.

## Quickstart: hunt

`hunt` reads exported logs offline: CloudTrail JSON or gzip, GCP Cloud Audit Logs, the Azure Activity Log, and usage CSV files with a documented column mapping.

```
cat > trail.json <<'EOF'
{"Records":[
{"eventID":"e1","eventTime":"2026-03-01T10:00:00Z","eventSource":"bedrock.amazonaws.com","eventName":"PutFoundationModelEntitlement","sourceIPAddress":"203.0.113.5","userIdentity":{"arn":"arn:aws:iam::111122223333:user/ci","accountId":"111122223333"}},
{"eventID":"e2","eventTime":"2026-03-01T10:04:00Z","eventSource":"bedrock.amazonaws.com","eventName":"InvokeModel","sourceIPAddress":"203.0.113.5","userIdentity":{"arn":"arn:aws:iam::111122223333:user/ci","accountId":"111122223333"}}
]}
EOF
jackproof hunt --source cloudtrail trail.json
```

```
jackproof hunt: 1 finding: 1 high

HIGH     JP-HUNT-001  arn:aws:iam::111122223333:user/ci enabled model access and invoked a model 4m0s later  [high confidence]
         e1 at 2026-03-01T10:00:00Z
           PutFoundationModelEntitlement by arn:aws:iam::111122223333:user/ci from 203.0.113.5
         e2 at 2026-03-01T10:04:00Z
           InvokeModel by arn:aws:iam::111122223333:user/ci from 203.0.113.5
         flags: unverified-rule
         fix: Confirm with the principal's owner that the enablement was planned. If it was not, disable the credential, remove the model access, and review every action the principal took in the window.
         id: 18ac35ef1281

Coverage
  log source: cloudtrail: trail.json, 2 relevant events
  time range for trail.json: 2026-03-01T10:00:00Z to 2026-03-01T10:04:00Z
  rules not verified against provider documentation: JP-HUNT-001, JP-HUNT-002, JP-HUNT-003, JP-HUNT-004, JP-HUNT-005, JP-HUNT-006, JP-HUNT-007, JP-HUNT-008
```

`jackproof hunt export-sigma` writes the same detections as Sigma rules. Thresholds come from `jackproof.yaml`.

## Other commands

| Command | Purpose |
| --- | --- |
| `report` | One report across all modules. Scan and posture always run. Add `--logs` with `--logs-source` for hunt, and `--fingerprints`, `--secret-names` or `--keys-stdin` for exposure. Formats: `md`, `html`, `json`, `sarif`, `text` |
| `diff <base> <head>` | Findings added between two git revisions, each checked out in an isolated worktree |
| `explain <finding-id> [path...]` | Full evidence, method, flags, unproven items and fix for one finding |
| `rules list`, `rules show <id>` | The rule catalogue |
| `scan --staged` | Scan the staged content of a repository, for a pre-commit hook |

Exit code 0 means no finding at or above `--fail-on` (default `high`), 1 means findings were found, and 2 means a usage or runtime error. See [docs/cli.md](docs/cli.md) for flags, the GitHub Action and the pre-commit hook.

## Limits

- An empty result never means a system is safe. Every report ends with a coverage section that lists what was and was not examined.
- Provider key formats, cloud permission names and log event names are marked `verified: false` until they are confirmed against official documentation. [docs/unverified.md](docs/unverified.md) lists them, and affected findings carry the `unverified-rule` flag.
- `scan` and `posture` are static analysis. Terraform is evaluated on a best-effort basis. Values from modules, remote state and runtime inputs are not resolved.
- Context-only keys, which have no distinctive prefix, are matched by variable name and reported with medium confidence.
- `posture` reads infrastructure code. Its opt-in `--live` mode adds read-only checks of model invocation logging: AWS Bedrock in one region, Vertex AI Data Access audit logs in one project, and the Azure OpenAI diagnostic settings of one subscription. It has no other live checks. Guardrails, budgets and quotas defined outside the scanned paths are reported as incomplete.
- `hunt` analyses exported logs. The Azure Activity Log does not record model invocations, so Azure coverage is limited to enablement and key operations.
- The only network calls are the opt-in checks of `exposure verify` and `posture --live`.

## Contributing rules

Rules are YAML files in `rules/`, one per rule, embedded at build time. Add a rule with an id of the form `JP-KEY-NNN`, `JP-POS-NNN`, `JP-HUNT-NNN` or `JP-EXP-NNN`, a severity, references, and either a `pattern` or a `matcher`. Load your own with `--rules-dir`. Mark a rule `verified: false` unless every fact in it is confirmed in official documentation. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Documentation

- [Evidence model](docs/evidence-model.md)
- [Configuration](docs/configuration.md)
- [Command line, CI and hooks](docs/cli.md)
- [Threat model](docs/threat-model.md)
- [Rules](docs/rules.md)
- [Unverified facts](docs/unverified.md)
- [Dependencies](docs/dependencies.md)
- [Security policy](SECURITY.md)

## License

Apache-2.0. See [LICENSE](LICENSE).
