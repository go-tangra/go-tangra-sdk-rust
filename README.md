# go-tangra-sdk-rust

A Rust SDK for building go-tangra v4 modules with the same wire behaviour as
a Go module built on `github.com/go-tangra/go-tangra/v4` (freya).

Crates:

- `tangra-proto` - the platform protos (`gateway.v1`, `auth.v1`, `lcm.v1`),
  vendored verbatim (see `crates/tangra-proto/SOURCES.md`) and compiled with
  tonic/prost.
- `tangra-sdk` - config, logging, error vocabulary, list queries, correlation,
  SPIFFE identity (file and lcm enrolment providers), mTLS (rustls), service
  policy, admin listener and the `App` runtime (axum HTTP + tonic gRPC);
  help docs (`helpdocs`), the UI remote (`ui`, feature `ui`), the Valkey
  event bus (`events`, feature `events`) and the catalogue descriptor
  (`catalogue`).

Status: work in progress (phases 1-2: foundation, identity, transport, runtime).

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

## Deviations from the Go framework

Behaviour follows go-tangra v4.10.0 unless listed here.

- **Request timeout** is enforced on the response future (HTTP `504
  {"reason":"timeout"}`, gRPC `DEADLINE_EXCEEDED`). In Go it is a context
  deadline that a handler has to observe.
- **gRPC message size**: set `max_decoding_message_size(limits.max_request_bytes)`
  on each generated server; grpc-go's `MaxRecvMsgSize` is not applied by the
  transport.
- **HTTP body limit** is a length-limited body (`http.MaxBytesReader`); axum's
  extractors answer 413 when it trips (audited as `limit_exceeded`).
- **Outbound clients** dial the `discovery.static` endpoints with
  per-connection failover instead of Kratos' per-request balancing.
  `client()` returns a `PeerChannel` (a tonic `GrpcService`), not a raw
  `Channel`. On a trust-bundle change the pool forgets its channels; channels
  callers still hold are not force-closed.
- **ALPN**: like Go, a client that offers no ALPN gets HTTP/1.1 on the HTTP
  listener, but a client offering only `http/1.1` is refused by rustls, where
  Go's `http11fallback` would accept it. The gRPC listener requires `h2`.
- **Tracing**: no OpenTelemetry export. The incoming W3C `traceparent` and
  `baggage` are carried (trace ID in logs, forwarded on outbound calls), as
  with Go's default no-op tracer provider.
- **Server address**: an empty `server.grpc_addr` disables gRPC. Go would
  still start a gRPC server on a random port.
- **lcm provider**: renewal runs in one task started by the first `watch`;
  Go starts one per `Watch` call. With a single watcher they behave the same.
- **pprof** does not exist in Rust; `admin.enable_pprof` is accepted and logged.
- **Policy decision cache**: no LRU cache. Decisions are the same.

### Help docs, UI, events, catalogue

- **Embedding** uses `include_dir` (`fstree::FileTree::from_embedded`): it
  always embeds (debug builds too, unlike `rust-embed`) and keeps the
  directory tree like `embed.FS`. Modules depend on `include_dir` directly
  (the macro names its crate); `tangra_sdk::include_dir` is the version the
  SDK accepts.
- **Help docs** match go-tangra v4.10.0 byte for byte on the committed
  fixtures (bundle JSON, digest, problem lists; see
  `crates/tangra-sdk/tests/fixtures/README.md`). YAML syntax errors are
  reported at the same file and line but worded by yaml-rust2, and a tab
  right after `key:` is a syntax error (yaml.v3 accepts it). CI can keep the
  Go `docs-lint` action; `tangra-docs-rs lint [dir]` gives the same output.
- **UI**: a non-canonical path (`/ui/a//b`, `/ui/../x`) is 404 here; Go's
  ServeMux first answers it with a 301 to the cleaned path. `/ui` (no
  slash) is 404 (Go: 301 to `/ui/`). Files served from disk
  (`Remote::from_dir`) are treated like embedded ones: no `Last-Modified`.
  Content types use Go's built-in table (what an alpine image without
  `/etc/mime.types` sees), then sniffing.
- **Events**: the connection dials `valkey.addresses` in order (valkey-go
  may treat several addresses as a cluster). The consumer pauses
  `retry_delay` (1s) after a failed read; Go retries at once.
- **Catalogue**: only the descriptor (`tangra-module.yaml`) is ported;
  `catalogue-entry.json`, `bundle.zip` and the attestation stay with the Go
  `catalogue-entry` action. Give it
  `permissions-command: cargo run -q --bin <module>-catalogue-permissions`,
  a binary calling `catalogue::print_permissions`. Host-input patterns are
  compiled with the `regex` crate (RE2 syntax; Unicode classes differ from
  Go's ASCII `\d`/`\w` only on non-ASCII input).
