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
    extensions, and a version pin.

Status: work in progress (phases 1-3: foundation, identity, transport,
runtime, gateway/auth platform integration).

```rust,ignore
let verifier = app.user_auth(auth::Config { issuer: cfg.gateway.issuer.clone(), ..Default::default() })?;
app.auth_registration(registration())?;           // 5s retry, then every 5 min
app.gateway_registration(manifest())?;            // after ready; deregisters on shutdown
let api = Router::new().route("/api/orders/v1/me", get(|u: auth::User| async move { u.user_id }))
    .layer(auth::UserAuthLayer::new(verifier));
app.run(Services::new().http(api)).await?;
```

The manifest validator and the token verifier are cross-checked against the
Go originals (portal `internal/manifest`, authclient `VerifyToken`, deployer
and warden route derivation); the fixtures and the Go programs that produced
the expected results are under `crates/tangra-sdk/tests/fixtures/`.

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
- **OpenAPI routes**: an operation that is both `x-freya-public` and carries
  `x-freya-permission` is refused (warden's rule); the deployer's builder
  lets `public` win.
