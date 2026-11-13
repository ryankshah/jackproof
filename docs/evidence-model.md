# Evidence model

Every module reports findings in the same shape. A finding says what was found, how it was found, how sure the tool is, and what the tool could not establish.

## Fields

| Field | Meaning |
| --- | --- |
| `id` | A 12 character hash of the rule id and the location of the first evidence entry. The same finding at the same place keeps the same id. |
| `rule` | The rule id, for example `JP-KEY-001`. |
| `module` | `scan`, `posture`, `hunt` or `exposure`. |
| `title` | One plain line that names the credential, identity or principal involved. |
| `severity` | `critical`, `high`, `medium`, `low` or `info`. |
| `confidence` | `high`, `medium` or `low`. |
| `evidence` | One or more entries. A file entry has a path and a line range. A log entry has a record id and a timestamp. Each entry has a short excerpt with secrets redacted. |
| `method` | How the finding was detected: `pattern`, `ast`, `iac-parse`, `policy-eval`, `log-correlation` or `fingerprint-match`. |
| `flags` | `inferred`, `config-implied`, `incomplete` or `unverified-rule`. |
| `unproven` | Plain sentences that name what the tool could not establish. |
| `remediation` | The next step. Posture findings include a ready-to-apply snippet after the first paragraph. |
| `refs` | URLs to provider or framework documentation. |

## Confidence

- **high**: the code, configuration or log record directly establishes every link in the claim.
- **medium**: one link rests on a heuristic, such as a variable name, a workload name, or an environment variable resolved from `.env.example`.
- **low**: the evidence is weak or partial. Low confidence findings are shown by default. `--min-confidence medium` hides them.

Severity says how bad the finding is if it is true. Confidence says how likely it is to be true. A high severity finding with medium confidence still deserves a look.

## Flags

- `inferred`: a link in the claim rests on a heuristic. The `unproven` list says which link.
- `config-implied`: the finding depends on what `jackproof.yaml` says, for example that an environment does not expect models.
- `incomplete`: the finding is about something that may be defined outside the scanned input, such as an organization guardrail.
- `unverified-rule`: the rule depends on a provider key format, API field, permission or log event name that has not been confirmed in official documentation. See [unverified.md](unverified.md).

## Redaction and fingerprints

jackproof never prints, logs, stores or transmits a full secret. A secret appears in redacted form: at most the first four and last four characters, fewer for short values. A secret is identified by its fingerprint, the first 16 hexadecimal characters of the SHA-256 digest of its exact bytes. Two locations with the same fingerprint hold the same secret.

## Coverage

An empty result never means safe. Every report ends with a coverage section:

- the files scanned, grouped by kind, and the files skipped with the reason
- the log sources read and the time range each one covers
- the rules, provider formats, permissions and client patterns that are marked unverified

## Example

```json
{
  "id": "ed688e864c41",
  "rule": "JP-KEY-001",
  "module": "scan",
  "title": "Anthropic key sk-a...xxxx committed in .env",
  "severity": "high",
  "confidence": "high",
  "evidence": [
    {
      "path": ".env",
      "start_line": 1,
      "end_line": 1,
      "excerpt": "ANTHROPIC_API_KEY=sk-a...xxxx"
    }
  ],
  "method": "pattern",
  "flags": ["unverified-rule"],
  "unproven": ["Whether the key is still active."],
  "remediation": "Revoke the key at the provider, create a replacement, store it in a secret manager and inject it at runtime. Removing the line from the file does not remove it from git history.",
  "refs": ["https://docs.github.com/en/code-security/secret-scanning/introduction/about-secret-scanning"]
}
```
