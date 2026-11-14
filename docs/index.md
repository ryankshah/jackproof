# jackproof

jackproof finds, scores, detects and responds to LLMjacking risk: the theft and resale of LLM access through stolen API keys, cloud credentials and model-service permissions. It is a single static Go binary. All analysis is offline unless you pass an explicit opt-in flag.

## Install

```
go install github.com/ryankshah/jackproof/cmd/jackproof@latest
```

On macOS and Linux with Homebrew:

```
brew install --cask ryankshah/tap/jackproof
```

Release archives, checksums and SBOMs are on the [releases page](https://github.com/ryankshah/jackproof/releases).

## Modules

| Command | Question it answers |
| --- | --- |
| `scan` | Where are the LLM credentials, and which workloads can read them |
| `posture` | Can an attacker turn on and abuse model services |
| `hunt` | Is it happening right now |
| `exposure` | A provider says a key leaked. What do I rotate, in what order |

Every finding carries its evidence, the method that produced it, a confidence level, and a list of what the tool could not establish.

## Documentation

- [Command line, CI and hooks](cli.md)
- [Configuration](configuration.md)
- [Evidence model](evidence-model.md)
- [Threat model](threat-model.md)
- [Rules](rules.md)
- [Unverified facts](unverified.md)
- [Verification record](verification.md)
- [Dependencies](dependencies.md)

The source code, the changelog and the security policy are in the [repository](https://github.com/ryankshah/jackproof).
