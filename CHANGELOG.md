# Changelog

This project follows semantic versioning. Entries list what changed for people who run the tool.

## 1.0.1 - 2026-11-14

### Changed

- The GitHub Action display name is now `jackproof LLMjacking scan`, so that it can be listed on the GitHub Marketplace. Workflows that use `ryankshah/jackproof` are not affected.

## 1.0.0 - 2026-11-14

First release.

### Added

- `scan`: finds literal LLM provider keys and references to them in code, environment files, Compose, Kubernetes, GitHub Actions, Dockerfiles, devcontainers, notebooks and Terraform. It builds a graph of the workloads that hold each credential and what a compromise of each one reaches. Rules `JP-KEY-001`, `JP-KEY-010`, `JP-KEY-020`, `JP-KEY-021`, `JP-KEY-030`, `JP-KEY-040` and `JP-KEY-050`.
- `scan`: links code to credentials that it fetches from AWS Secrets Manager, Google Secret Manager, Azure Key Vault or Vault, when the secret name identifies an LLM provider.
- `scan`: words each key finding by git state. A key in a tracked file is reported as committed. A key in a file that git ignores is reported at low severity.
- `scan --staged`: scans the staged content of a repository, for a pre-commit hook.
- `posture`: reads Terraform for AWS, GCP and Azure and reports identities that can enable or abuse model services, and missing guardrails, logging, budgets and quotas. Rules `JP-POS-001` to `JP-POS-007`. Each finding carries a ready-to-apply remediation snippet.
- `posture --live`: read-only checks of model invocation logging for AWS Bedrock, Vertex AI and Azure OpenAI.
- `hunt`: reads exported CloudTrail, Google Cloud Audit Log, Azure Activity Log and usage CSV files and reports enable-then-invoke sequences, volume spikes, first-seen models, many or unfamiliar source addresses, key creation followed by use elsewhere, reconnaissance, unmapped principals and streaming bursts. Rules `JP-HUNT-001` to `JP-HUNT-008`, with thresholds in `jackproof.yaml`.
- `hunt export-sigma`: writes the detections as Sigma rules.
- `exposure`: matches fingerprints, secret names or raw keys from an exposure notice against everything that defines, references or injects them, and writes a rotation plan ordered by blast radius. Rules `JP-EXP-001` to `JP-EXP-003`.
- `exposure verify`: an opt-in live check, with `--verify-live` and `--i-own-these-keys`, that old keys are rejected. It sends one read-only request per key and never calls a model.
- `report`: one report across all four modules, as text, Markdown, HTML, JSON or SARIF.
- `diff`: findings that a pull request adds, with each revision checked out in an isolated git worktree.
- `explain`: the full evidence, method, flags, unproven items and fix behind one finding.
- A GitHub Action, a pre-commit hook, a distroless non-root Docker image and a GoReleaser configuration.
- Documentation: evidence model, configuration, command line, threat model, the rule catalogue, and the list of facts that are not yet verified against provider documentation.

### Known limits

- Some provider key formats, role entries, live-check endpoints and log event names are marked `verified: false` until they are confirmed in official documentation. `docs/unverified.md` lists them, and `docs/verification.md` records what is confirmed and where.
- `scan` and `posture` are static analysis. Terraform is evaluated on a best-effort basis, and module inputs and remote state are not resolved.
- `posture --live` checks logging for one region, project or subscription at a time, and the Google Cloud check cannot see audit settings inherited from a folder or the organization.
- The Azure Activity Log does not record model invocations.
- Release archives are not signed.
