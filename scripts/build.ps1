$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$version = (git -C $root describe --tags --always --dirty 2>$null)
if (-not $version) { $version = "dev" }

$outDir = Join-Path $root "bin"
New-Item -ItemType Directory -Force $outDir | Out-Null

$env:CGO_ENABLED = "0"
go build -C $root -trimpath -ldflags "-s -w -X main.version=$version" -o (Join-Path $outDir "jackproof.exe") ./cmd/jackproof
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
