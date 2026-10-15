# go-tangra-sdk-rust

A Rust SDK for building go-tangra v4 modules with the same wire behaviour as
a Go module built on `github.com/go-tangra/go-tangra/v4` (freya).

Crates:

- `tangra-proto` - the platform protos (`gateway.v1`, `auth.v1`, `lcm.v1`),
  vendored verbatim (see `crates/tangra-proto/SOURCES.md`) and compiled with
  tonic/prost.
- `tangra-sdk` - config, logging, error vocabulary, list queries, correlation,
  SPIFFE identity (file and lcm enrolment providers), mTLS (rustls), service
  policy, admin listener and the `App` runtime (axum HTTP + tonic gRPC).

Status: work in progress (phases 1-2: foundation, identity, transport, runtime).

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```
