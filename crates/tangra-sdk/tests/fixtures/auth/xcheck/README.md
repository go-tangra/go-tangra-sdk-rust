# Token verification cross-check

`../expected.go.json` is authclient `VerifyToken` (auth `sdk/v4.3.0`,
commit 1ce08a764f19e40a5061b7bb8cb3c3f36cafea98, golang-jwt v5.3.1) run over
`../tokens.json` at the fixtures' instant. To regenerate: put `main.go`
and `go.mod.txt` (as `go.mod`) in a scratch directory next to
`git archive sdk/v4.3.0 sdk` of the auth repository extracted as
`../authsrc`, then `GOWORK=off GOFLAGS=-mod=mod go run . <fixtures/auth>`.
