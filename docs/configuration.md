# Configuration

jackproof reads `jackproof.yaml` from the first path you pass, or from the directory you run it in. Use `--config` to name a file. A missing file means defaults. An unknown key is an error, so a typo does not silently disable a setting.

## Reference

```yaml
ignore:
  paths:
    - "vendor/**"
    - "**/*.min.js"
  rules:
    - JP-KEY-030

environments:
  dev: ["deploy/dev/**"]
  eval: ["deploy/eval/**"]
  prod: ["deploy/prod/**", "**/prod.env"]

expected_providers:
  dev: [bedrock]
  prod: []

owned_accounts:
  - "111122223333"

hunt:
  enable_then_invoke_window: 1h
  distinct_ips: 5
  known_networks:
    - 203.0.113.0/24
```

### ignore

- `paths`: glob patterns for files and directories to skip. `*` matches within one path segment and `**` matches across segments. Paths are relative to the scan root and use forward slashes. Skipped files appear in the coverage section.
- `rules`: rule ids to drop from the output.

### environments

Maps an environment name to path globs. A workload gets the environment of the first glob that matches the file that defines it. GitHub Actions jobs use the name of their `environment:` key, and Kubernetes workloads use their namespace when it equals a configured environment name. The environment drives `JP-KEY-010`, which reports a credential shared across environments.

### expected_providers

Maps an environment to the model services it is expected to use: `bedrock`, `vertex-ai`, `gemini-api` or `azure-openai`. `posture` reports an identity that can enable a service that its environment does not list. An environment with no entry is treated as unknown, and the finding drops to medium confidence. An empty list means no models are expected.

### owned_accounts

Account ids that belong to you. `hunt` reports model invocations in any other account with `JP-HUNT-007`.

### hunt

Thresholds for the detections. Durations use Go syntax, such as `30m` or `2h`.

| Key | Default | Used by |
| --- | --- | --- |
| `enable_then_invoke_window` | `1h` | `JP-HUNT-001`: time allowed between enabling a service and invoking a model |
| `volume_multiplier` | `5` | `JP-HUNT-002`: multiple of the baseline median that raises an alert |
| `volume_period` | `1h` | `JP-HUNT-002`: size of one counting period |
| `baseline_periods` | `24` | `JP-HUNT-002`: earlier periods in the rolling median |
| `baseline_min_periods` | `3` | `JP-HUNT-002`: earlier periods needed before a baseline counts |
| `min_requests` | `20` | `JP-HUNT-002`: smallest count that can raise an alert |
| `min_history` | `20` | `JP-HUNT-003`, `JP-HUNT-004`: invocations a principal needs before anything is new for it |
| `high_cost_models` | `*opus*`, `*gpt-4*`, `*o1*`, `*ultra*` | `JP-HUNT-003`: model name globs that raise severity to high |
| `distinct_ips` | `5` | `JP-HUNT-004`: addresses per principal within the window |
| `distinct_ip_window` | `10m` | `JP-HUNT-004` |
| `key_use_window` | `10m` | `JP-HUNT-005`: time allowed between creating a key and using it elsewhere |
| `recon_window` | `30m` | `JP-HUNT-006`: time allowed between listing models and the first invocation |
| `stream_concurrency` | `20` | `JP-HUNT-008`: streaming requests within the window |
| `stream_window` | `1m` | `JP-HUNT-008` |
| `uniform_share` | `0.9` | `JP-HUNT-008`: share of requests that use the same model and client |
| `known_networks` | none | `JP-HUNT-004`: CIDR ranges of your own egress |

Every alert states the baseline it used and lists the records that triggered it. The defaults are a starting point. Tune them against your own logs.

## Source address enrichment

`jackproof hunt --asn-map file.csv` reads a CSV with the columns `cidr,asn,org,class`. A class of `hosting` marks a hosting provider. jackproof has no built-in address database, so it makes no network lookups.

## Usage CSV files

`jackproof hunt --source usage` reads a CSV with a header row. The default columns are `timestamp`, `principal`, `model`, `requests`, `cost` and `source_ip`. Only `timestamp` and `principal` are required. Rename columns with `--usage-columns timestamp=ts,principal=api_key_id`. A timestamp is RFC 3339, a date, or Unix seconds.
