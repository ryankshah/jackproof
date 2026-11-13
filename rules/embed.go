package rules

import "embed"

//go:generate go run ../internal/docgen -out ../docs

//go:embed *.yaml
var FS embed.FS
