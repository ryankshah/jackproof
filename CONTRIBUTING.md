# Contributing

## Set up

You need Go 1.26 or newer and git.

```
git clone https://github.com/ryankshah/jackproof
cd jackproof
git config core.hooksPath .githooks
make check
```

`make check` runs `go vet`, staticcheck, golangci-lint and the tests. Install staticcheck and golangci-lint with `go install`. CI runs the same checks on Linux, macOS and Windows.

## Code rules

- No comments of any kind. Names and structure carry the meaning. The only allowed `//` lines are the compiler directives `//go:build`, `//go:embed` and `//go:generate`. A test fails if a comment appears in Go, YAML, shell or Dockerfile source.
- No dead code, no placeholder functions, no unused parameters, no speculative abstractions. Add an interface only when two real implementations exist.
- Standard library first. Each third-party dependency needs a one-line reason in [docs/dependencies.md](docs/dependencies.md).
- Pure Go. No cgo.
- Wrap errors with `fmt.Errorf("...: %w", err)`. Never swallow one.
- Tests are table-driven and sit next to the code. Every detector has positive and negative fixtures.
- Test fixtures must not contain strings that match real provider key formats. Build them at run time from fragments, for example `"sk-" + "ant-" + strings.Repeat("x", 90)`.

## Writing rules

Use plain, precise, technical English with short sentences. Say what something does. Do not use emojis, exclamation marks, em dashes, rhetorical questions, or the words and phrases that tests reject. A test checks the README, the docs, the rule files and every user-facing string in the code.

If a provider key format, API field, permission or log event name is not confirmed in the provider's official documentation, mark the rule `verified: false`. The generated [docs/unverified.md](docs/unverified.md) lists it.

## Add a rule

1. Create `rules/JP-<FAMILY>-NNN.yaml`. The file name is the rule id. Families are `KEY` for scan, `POS` for posture, `HUNT` for hunt and `EXP` for exposure.
2. Give it a `title`, `severity`, `verified`, `description`, `remediation`, at least one `refs` URL over https, and exactly one of `pattern` or `matcher`.
3. A `pattern` rule matches a regular expression against every text line the scanner reads. A `matcher` rule names a detector written in Go. Write the detector, with positive and negative fixtures.
4. Run `go generate ./...` to refresh `docs/rules.md` and `docs/unverified.md`.

To try a rule without changing the repository, put the file in a directory and pass `--rules-dir`.

## Commits

- Imperative subject of 72 characters or fewer, no trailing period, and a lowercase type prefix from `feat`, `fix`, `refactor`, `test`, `docs`, `build`, `ci` or `chore`. Example: `feat(scan): detect provider keys in compose env blocks`.
- One coherent change per commit. Do not commit a failing build or failing tests.
- Do not add attribution trailers or footers. The `commit-msg` hook rejects them.

## Changes that need discussion first

Open an issue before you change the command line surface, the finding schema or the rule id scheme.
