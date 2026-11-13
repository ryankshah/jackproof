# Dependencies

Each third-party module has one reason to exist. The standard library is used everywhere else.

| Module | Reason |
| --- | --- |
| go.yaml.in/yaml/v3 | Parses the rule catalogue, the provider catalogue, `jackproof.yaml`, and the Compose, Kubernetes and GitHub Actions files that `scan` reads. The standard library has no YAML parser. |
