# Security policy

## Report a vulnerability privately

Do not open a public issue for a security problem. Use GitHub private vulnerability reporting: open the Security tab of the repository and choose Report a vulnerability. If that option is not available, contact the repository owner through the address on their GitHub profile and ask for a private channel before you share details.

Include:

- the version or commit you tested
- what you did and what happened
- what you expected to happen
- whether the problem exposes a secret, runs unintended code, or causes a network call that was not requested

The maintainer will acknowledge the report, work with you on a fix, and agree a disclosure date with you.

## What counts

- jackproof prints, logs, stores or transmits a full secret.
- jackproof makes a network call that the user did not enable with a flag.
- `exposure verify` calls a model, calls anything other than the documented read-only request, or follows a redirect with a credential.
- A crafted repository, manifest, Terraform file or log makes jackproof execute code, read files outside the scanned paths, or write files outside its own temporary directories.

## Design commitments

- A secret is shown only in redacted form and as a fingerprint.
- All analysis is offline by default. The only network calls are the opt-in checks of `exposure verify`, and they need `--verify-live` and `--i-own-these-keys`.
- Raw keys passed to `exposure --keys-stdin` are hashed in memory and never stored or echoed.
- Test fixtures never hold strings that match real provider key formats. They are assembled at run time from fragments.

## Supported versions

Security fixes go to the latest release and to the default branch.
