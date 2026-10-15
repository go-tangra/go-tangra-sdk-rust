# Manifest cross-check against the Go originals

Generated files (do not edit by hand):

- `../json/*.json` - `gen_json.py ..` (valid.json is portal
  `internal/manifest/testdata/valid.json`; the cases port
  `manifest_test.go` plus boundary cases).
- `../pb/rust_*.pb` - `TANGRA_WRITE_XCHECK=1 cargo test --test manifest_xcheck`.
- `../pb/go_deployer.pb`, `../deployer_routes.go.json` (and the warden
  pair) - `module_main.go` run as `cmd/xcheck` inside `git archive`
  copies of the deployer / warden repositories (warden: import
  `pkg/wardenmanifest`): `GOWORK=off GOFLAGS=-mod=mod go run ./cmd/xcheck <routes.json> <manifest.pb>`.
- `../expected.go.json` - `portal_main.go` run as `cmd/xcheck` inside a
  `git archive` copy of the portal repository (it imports the portal's
  `internal/manifest`, so it must live inside that module):
  `GOWORK=off GOFLAGS=-mod=mod go run ./cmd/xcheck <fixtures/manifest>`.

`../deployer.yaml` and `../warden.yaml` are the modules'
`api/openapi/*.yaml`, copied verbatim.

Sources (origin/main, 2026-10-15):

- deployer 288cc26dea9aa370792640f01632d80537a205c5
- warden 66b50f21c03d7b89c52f48694ad95b260749aed9
- portal f36c527492b804a599101398fad4735d2ab783ec
