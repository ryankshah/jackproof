# Dependencies

Each third-party module has one reason to exist. The standard library is used everywhere else.

| Module | Reason |
| --- | --- |
| go.yaml.in/yaml/v3 | Parses the rule catalogue, the provider catalogue, `jackproof.yaml`, and the Compose, Kubernetes and GitHub Actions files that `scan` reads. The standard library has no YAML parser. |
| github.com/hashicorp/hcl/v2 | Parses Terraform files with source line numbers. Evidence for `scan` and `posture` needs the exact lines of the resources it cites. The standard library cannot parse HCL. |
| github.com/zclconf/go-cty | Value model used by the HCL evaluator. Needed to evaluate `jsonencode`, variables and locals in Terraform policies. Pulled in by hcl. |
