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
