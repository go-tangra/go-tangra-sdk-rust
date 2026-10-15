# Vendored protos

Copied verbatim (byte-for-byte) from `origin/main` of each repository on
2026-10-15. Do not edit; re-vendor and update this table instead.

| File | Repository | Path | Commit |
|---|---|---|---|
| `proto/gateway/v1/gateway.proto` | github.com/go-tangra/go-tangra-portal-v4 | `sdk/api/proto/gateway/v1/gateway.proto` | `f36c527492b804a599101398fad4735d2ab783ec` (identical to tag `sdk/v4.2.0`) |
| `proto/auth/v1/auth.proto` | github.com/go-tangra/go-tangra-auth | `sdk/api/proto/auth/v1/auth.proto` | `5f1aba1b3b65e6700e530bc5ba4085828c2a4716` (identical to tag `sdk/v4.4.0`) |
| `proto/lcm/v1/lcm.proto` | github.com/go-tangra/go-tangra-lcm-v4 | `sdk/api/proto/lcm/v1/lcm.proto` | `72c23f60e13efb4244a230b6037c9177bffc6384` |

Imports are only the protobuf well-known types (`google/protobuf/duration.proto`,
`struct.proto`, `timestamp.proto`), taken from `protoc-bin-vendored`'s include
path and mapped to `prost-types`.

SHA-256 of the vendored files:

```
d5cea1783a0e120b3b05e99b5114c818fb07eb7516166b870cd4928c163ef3aa  auth/v1/auth.proto
03175fd6c091014349de9819a1651ea403b52f4cbff185667b7c824d5574d7ea  gateway/v1/gateway.proto
64f8e96455010eb952ead633750cf6b6dfcb39b7bc74651792ed36ccf3115561  lcm/v1/lcm.proto
```
