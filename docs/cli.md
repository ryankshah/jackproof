# Command line, CI and hooks

## Common flags

These flags exist on `scan`, `posture`, `hunt`, `exposure`, `report`, `diff` and `explain`.

| Flag | Default | Meaning |
| --- | --- | --- |
| `--format` | `text` (`md` for `report` and `exposure`) | `text`, `json`, `sarif`, `md` or `html` |
| `--config` | `jackproof.yaml` in the first path | Path to the configuration file |
| `--rules-dir` | none | Directory of extra rule files, merged with the built-in catalogue |
| `--min-confidence` | none | Hide findings below `high`, `medium` or `low` |
| `--fail-on` | `high` | Exit with status 1 when a finding has at least this severity |

Flags may come before or after paths. Exit code 0 means no finding at or above `--fail-on`. Exit code 1 means findings were found. Exit code 2 means a usage or runtime error.

## Commands

- `scan [path...]`: credentials, references and the holders that can read them. `--staged` scans the staged content of the current git repository.
- `posture [path...]`: Terraform for AWS, GCP and Azure. `--live` also checks AWS Bedrock invocation logging with one signed, read-only `GetModelInvocationLoggingConfiguration` request. It reads `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and an optional `AWS_SESSION_TOKEN` from the environment, takes the region from `--region`, `AWS_REGION` or `AWS_DEFAULT_REGION`, and checks that one region. It does not read AWS profile files or run any other live check.
- `hunt --source <type> <files...>`: `cloudtrail`, `gcp`, `azure` or `usage`. Optional `--graph scan.json`, `--asn-map file.csv` and `--usage-columns`.
- `hunt export-sigma`: Sigma rules for the detections.
- `exposure [path...]`: needs at least one of `--fingerprints file`, `--secret-names file` or `--keys-stdin`. `--fp-algo` names the algorithm of the fingerprints: `sha256` (default), `sha1` or `sha512`. A SHA-256 fingerprint may be the full digest or its first 16 characters.
- `exposure verify`: needs `--keys-stdin`, `--verify-live` and `--i-own-these-keys`. Sends one read-only metadata request per key to its provider, never calls a model, and exits with status 1 unless every key is rejected.
- `report [path...]`: all four modules in one report. Scan and posture always run. `--logs file` (repeatable) with `--logs-source type` adds hunt, and it cross-references the scan graph on its own. `--fingerprints`, `--secret-names` or `--keys-stdin` adds exposure and the rotation plan. `--asn-map` and `--usage-columns` work as they do for `hunt`.
- `diff <base> <head>`: scan and posture at two revisions, each in an isolated git worktree. The report lists the findings that the head revision adds, and the extras list what was removed or changed. Only added findings affect the exit code.
- `explain <finding-id> [path...]`: the full record of one finding. An id prefix of at least six characters is enough. Use `--from report.json` to read a saved JSON report instead of analysing again.
- `rules list`, `rules show <id>`.

## GitHub Action

```yaml
on: pull_request

permissions:
  contents: read
  pull-requests: write
  security-events: write

jobs:
  jackproof:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: ryankshah/jackproof@main
        with:
          strict: "true"
          fail-on: high
```

The action installs jackproof, runs `jackproof diff` between the pull request base and head, posts one comment and updates it on later runs, and uploads a SARIF report of the head revision to code scanning. It fails the job only when `strict` is true and the pull request adds a finding at or above `fail-on`. Pull requests from forks get no comment, because their token is read-only.

## pre-commit

```yaml
repos:
  - repo: https://github.com/ryankshah/jackproof
    rev: main
    hooks:
      - id: jackproof-scan
```

The hook runs `jackproof scan --staged --fail-on high`. It scans the staged content, not the working tree.

## Docker

The image is distroless and runs as a non-root user. Mount the code read-only and run with a read-only root file system:

```
docker run --rm --read-only -v "$PWD:/work:ro" jackproof scan .
```

The image has no git, so `diff` and `scan --staged` need the binary on the host.
