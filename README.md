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
  platform integration:
  - `auth` - offline EdDSA token verification (keys from `auth.v1.Keys/List`
    or JWKS, revocations from `auth.v1.Sessions/RevokedSince`), the axum
    `User` extractor and `UserAuthLayer`, permission/role/grant
    `Registration`, and `AuthzClient` (`Check`, `BatchCheck`, `ListMembers`);
  - `gateway` - the `gateway.v1.Registry` register/renew/deregister loop;
  - `manifest` - the gateway manifest builder, the gateway's own validation
    (schema + semantic rules), routes derived from OpenAPI `x-freya-*`
    extensions, and a version pin;
  module features: help docs (`helpdocs`), the UI remote (`ui`, feature `ui`), the Valkey
  event bus (`events`, feature `events`) and the catalogue descriptor
  (`catalogue`).
- `tangra-notes` (`examples/notes`) - an example module using all of the
  above, structured like the Go reference module (go-tangra-deployer): API,
  manifest from OpenAPI, auth and gateway registration, help pages, a Vue
  remote, events, catalogue descriptor, install bundle, Dockerfile. See
  [Writing a go-tangra module in Rust](docs/writing-a-module.md).

`tangra_sdk::testutil` holds test helpers for module authors: an in-test
SPIFFE CA, an in-memory identity, and `testutil::platform`, fake `gateway`
and `auth` services served over mTLS.

Status: phases 1-5 are done (foundation, identity, transport, runtime,
gateway/auth integration, help docs, UI, events, catalogue, the example
module). Nothing is published: there is no crates.io release and no
released module image. The behaviour is cross-checked against the Go
sources on the fixtures below; it has not run against a live core.

## Quick start

```rust,ignore
let cfg = Config::<MyConfig>::load("config.yaml")?;   // framework keys + module sections
let app = App::builder(cfg.framework).build().await?;  // mTLS listeners, policy, admin
let verifier = app.user_auth(auth::Config { issuer: cfg.module.gateway.issuer.clone(), ..Default::default() })?;
app.auth_registration(registration())?;               // 5s retry, then every 5 min
app.gateway_registration(manifest())?;                // after ready; deregisters on shutdown
let api = Router::new().route("/api/orders/v1/me", get(|u: auth::User| async move { u.user_id }))
    .layer(auth::UserAuthLayer::new(verifier));
app.run(Services::new().http(api)).await?;
```

The example module, end to end:

```sh
cargo test -p tangra-notes                      # unit, manifest, docs, catalogue, e2e
(cd examples/notes/ui && NODE_AUTH_TOKEN=... npm ci && npm run build)
cargo build -p tangra-notes --features ui       # embeds ui/dist
cargo run -p tangra-notes -- -config <config.yaml>
```

`examples/notes/tests/module.rs` runs the module against the fake platform;
its event checks need a Valkey (`TANGRA_TEST_VALKEY_ADDR=host:port`, or a
`valkey-server`/`redis-server` binary via `VALKEY_SERVER` or `PATH`).

The manifest validator and the token verifier are cross-checked against the
Go originals (portal `internal/manifest`, authclient `VerifyToken`, deployer
and warden route derivation); the fixtures and the Go programs that produced
the expected results are under `crates/tangra-sdk/tests/fixtures/`.

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

CI (`.github/workflows/ci.yaml`) runs these, lints the example's help pages
with the go-tangra `docs-lint` action, builds the example UI and image (not
pushed). A module repository's pipeline, with GHCR tags and the catalogue
entry, is `templates/module/.github/workflows/release.yaml`.

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

### Auth, gateway, manifest

Platform packages (auth `sdk/v4.3.0` authclient, portal `sdk/v4.2.0`
gatewayclient) follow Go unless listed here.

- **Gateway build version**: Go falls back to the main module version from
  the Go build info; Rust has none the SDK can read, so call
  `gateway::set_build_version(env!("CARGO_PKG_VERSION"))` (or set
  `Options::build_version`).
- **Gateway wiring validates up front**: `App::gateway_registration` runs the
  gateway's manifest validation and the docs-digest check when called and
  returns an error, where a Go module would register and be refused
  (`manifest_invalid`) at the maximum backoff forever.
- **Platform channels** are resolved from the app's client pool on every
  call (`ServiceConn`), so a trust-bundle rotation is picked up; Go modules
  keep the `ClientConn` obtained at start.
- **Ready hooks are awaited on shutdown** (at most 6s) so the gateway lease
  is withdrawn before the client pool closes; Go's deregistration races
  process exit.
- **Token JSON**: claims are decoded with encoding/json's rules
  (case-insensitive names, last duplicate wins, `null` keeps a string,
  quoted NumericDates). Invalid UTF-8 inside a claim string is refused here
  (Go replaces it with U+FFFD and decodes on).
- **JWKS over HTTPS** (`HttpKeys`) does not follow redirects (Go's
  `http.Client` follows up to 10) and parses JWK fields case-sensitively.
- **Ed25519** verification uses ring (cofactorless, canonical `S`, like Go's
  `crypto/ed25519`); behaviour on non-canonical public-key encodings is not
  cross-checked.
- **Log attributes** holding lists (`sample`, `roles` in the registration
  logs) are rendered as one string; slog writes a JSON array.
- **OpenAPI request validation**: routes are derived from the OpenAPI
  document, but requests are not validated against it (the deployer runs
  kin-openapi's `ValidateRequest`); handlers check parameters and bodies
  themselves (see `examples/notes/src/api.rs`).
- **OpenAPI routes**: an operation that is both `x-freya-public` and carries
  `x-freya-permission` is refused (warden's rule); the deployer's builder
  lets `public` win.
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
