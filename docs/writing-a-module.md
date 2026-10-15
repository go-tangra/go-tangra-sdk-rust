# Writing a go-tangra module in Rust

This guide builds a v4 module with `tangra-sdk` in the shape of the Go
reference module (go-tangra-deployer). Every step points at the working
example, [`examples/notes`](../examples/notes): a tenant-scoped notes module
with an API, help pages, a UI remote, events, a catalogue entry and an image.
Read the files next to each step; this page only says what each one is for.

The SDK matches the Go wire behaviour (go-tangra v4.10.0, portal sdk v4.2.0,
auth sdk v4.3.0). Where it differs, the [README](../README.md#deviations-from-the-go-framework)
lists it.

## 1. Crate

One binary crate with a library, so integration tests can build the module
in-process:

```
Cargo.toml          tangra-sdk (feature events if you publish events), axum, tokio, include_dir
build.rs            embeds ui/dist when built; stamps NOTES_VERSION
src/lib.rs          config, manifest, module, api, store, docs, remote
src/main.rs         -config / bootstrap / --healthcheck / version
src/bin/<module>-catalogue-permissions.rs
api/openapi/<module>.yaml
docs/help/
ui/
deploy/bundle/      config.yaml, policy.yaml, compose.yaml (templates)
tangra-module.yaml
testdata/manifest.sha256
Dockerfile
```

The SDK is not published to crates.io; depend on it by path or by git.
Cargo features mirror Go build tags: `ui` embeds the built remote.

## 2. Configuration — `src/config.rs`

`tangra_sdk::config::Config<M>` reads one YAML file strictly: the framework
keys (`service_name`, `trust_domain`, `env`, `identity`, `authz`, `limits`,
`admin`, `discovery`, `server`) into `FrameworkConfig`, every other key into
your `M`. Give `M` and each section `#[serde(default, deny_unknown_fields)]`
and put defaults on each section's `Default` (a partly given section is
filled from it, as yaml.v3 decodes over the whole default). Validate the
framework (`FrameworkConfig::validate`) and your sections, refusing insecure
options when `is_production()`. There are no environment overrides; the
install renders `${...}` placeholders into the file.

The deployer's sections, reused by notes: `gateway.{service,issuer}`,
`valkey` (`tangra_sdk::events::ValkeyConfig`), `events.enabled`, `enroll`
(`tangra_sdk::config::EnrollConfig`).

## 3. Identity — `src/module.rs`

Choose the provider as the deployer's `app.Build` does:

- production: `identity.provider: provided` plus `enroll.enabled`: build
  `identity::lcm::NetConfig::from_config(&fw, &enroll)`, then
  `LcmProvider::new(..)`, and pass it to `AppBuilder::identity_provider`
  (first enrolment with the join token, renewal over mTLS, `/state/svid.json`);
- development: `identity.provider: file` (PEM files, polled);
- tests: `testutil::MemoryProvider` with an SVID from `testutil::TestCa`.

`App::builder(cfg.framework).build().await` then validates the
configuration, checks the SVID matches `spiffe://<td>/svc/<service_name>`,
loads the service policy and binds the mTLS listeners and the admin
listener (`/healthz`, `/readyz`, `/metrics`).

## 4. Manifest — `src/manifest.rs`, `api/openapi/notes.yaml`

Declare every route once, in OpenAPI, with `x-freya-permission:
'<resource>:<action>'` or `x-freya-public: true` (optionally
`x-freya-timeout-seconds`, `x-freya-max-body-bytes`,
`x-freya-client-address`). `manifest::openapi::routes(doc, &perms)`
derives the gateway routes and refuses undeclared permissions. Build the
`Manifest` with the prefix (`/api/<module>`), permissions, CASL abilities,
nav entries (icons from the `@go-tangra/ui` kit set) and exposes
(`./routes`, `./nav`, `./boot`).

Bump the manifest version on every change: the gateway refuses changed
content under the same version (`manifest_drift`). Pin it with a test
(`tests/manifest.rs`, `manifest::pin::check`); refresh with
`TANGRA_UPDATE_MANIFEST_PIN=1 cargo test`.

## 5. Platform wiring — `src/module.rs`

On the built `App`:

- `app.user_auth(auth::Config { issuer, .. })` — a token verifier fed by
  auth's `Keys/List` and `Sessions/RevokedSince` over mTLS;
- `app.auth_registration(registration)` — permissions, module roles and
  built-in grants (`auth::Registration`), retried every 5s, then every 5
  minutes;
- `app.gateway_registration_with(service, gateway::Options { manifest,
  docs_digest, .. })` — the lease, renewed and withdrawn on shutdown; the
  manifest and digest are validated here, not at the gateway;
- `gateway::set_build_version(VERSION)` in `main` (Go stamps it with
  ldflags; notes takes `NOTES_VERSION` at build time).

These start once the app is ready. `discovery.static` names `gateway`,
`auth` (and `lcm`) for the client pool.

## 6. Routes and authorization — `src/api.rs`

The gateway enforces each route's permission, then proxies with the path
unchanged. In the module:

- protect routes with `.route_layer(UserAuthLayer::new(verifier))` and take
  `auth::User` (user, tenant, roles) in handlers; public routes go outside
  the layer;
- scope every read and write to `user.tenant_id`; another tenant's object is
  `404`;
- finer rules are yours: notes asks auth with
  `AuthzClient::check(CheckRequest { resource, action, .. })`;
- answer refusals with `error::ApiError` (`{"reason"[,"detail"]}`), success
  with `error::json` (Go encoder output, `no-store`), and set
  `error::set_secure_headers` on every response;
- lists: `listquery::parse` against a `Spec` (the sort allow-list),
  `ApiError::invalid_param(e.param)` on errors, `listquery::Page` as the
  body (`order_by` for SQL, `sort_slice`/`window` in memory);
- the app replaces router fallbacks: add a catch-all route for
  `404 not_found` and a fallback on each method router for `405`.

The SDK has no OpenAPI request validator (the deployer uses kin-openapi);
validate parameters and bodies in the handlers with the same outcomes
(`400 malformed_body`, `422 validation_failed`, `413 body_too_large`).

Storage: notes keeps notes in memory. A real module uses PostgreSQL (sqlx)
with migrations applied by `bootstrap` and at start, `sslmode=verify-full`
in production, the tenant in every query.

## 7. Help pages — `docs/help`, `src/docs.rs`

Markdown with front-matter (`title`, `summary`, `kind`, `order`, `tags`,
`requires`, `audience`); `index.md` is required; `requires` must be one of
your permissions. Embed with `include_dir!`, load with `helpdocs::load` (a
broken tree refuses to start), mount `helpdocs::router(bundle,
AllowServices::new([gateway]))` and announce `bundle.digest()` at
registration. Lint locally with `cargo run -p tangra-sdk --bin
tangra-docs-rs -- lint docs/help`; CI uses the go-tangra `docs-lint` action.

## 8. UI — `ui/`, `src/remote.rs`

A Vue 3 module-federation remote (`@module-federation/vite`): name = the
module, `remoteEntry.js`, `manifest: true`, exposes `./routes`, `./nav`,
`./boot`, the platform singletons host-only in production, `base:
/m/<module>/`. `@go-tangra/ui` comes from npm.pkg.github.com
(`NODE_AUTH_TOKEN`). `npm run build` writes `ui/dist`; with feature `ui`
the binary embeds it and serves it with `ui::router` at `/ui/*`, which the
gateway relays from `/m/<module>/`.

## 9. Events — `src/api.rs`

With feature `events`: `events::Client::connect(&valkey)` and
`events::Publisher::new(client).publish(tenant, &Target::All |
Target::Users(ids), "<module>.<event>", &data)` append to
`platform:events:<tenant>`, which the gateway fans out over SSE. Keep
payloads small and free of content the audience may not read. Consume other
modules' events with `events::consume`.

## 10. Packaging — `Dockerfile`, `deploy/bundle`, `src/healthcheck.rs`

Multi-stage: node (UI, npm token as a BuildKit secret), rust (`--features
ui`, version stamped), `debian:bookworm-slim` with `ca-certificates`, user
10001, `/state` 0700. The image has no wget/curl, so the compose
healthcheck runs `<binary> --healthcheck -config /app/config.yaml`
(`GET /readyz` on the loopback admin listener).

`deploy/bundle` holds the install templates the gateway renders:
`config.yaml` (production, `provided` identity + `enroll`, file policy,
discovery of the core services, Valkey over TLS), `policy.yaml` (only the
gateway reaches the module) and `compose.yaml` (mesh ports bound to
`MODULE_BIND_IP`, `FREYA_ADVERTISE_HOST`, the token, the state volume).
Only reserved placeholders (`TRUST_DOMAIN`, `GATEWAY_ISSUER`,
`LCM_ENROLL_URL`, `AUTH_GRPC`, `GATEWAY_GRPC`, `LCM_GRPC`,
`MESH_TENANT_ID`, `MODULE_*`, `GEN_*`) and declared host inputs may appear.

## 11. Catalogue — `tangra-module.yaml`

The spec-035 descriptor: module, image, route prefixes and names, minimum
core versions, the bundle and its templates, host inputs with patterns.
Validate it in a test with `catalogue::parse_descriptor`, render the
templates with sample values and load the result as a production config
(`tests/catalogue.rs`). The release job needs a permissions command: a tiny
binary calling `catalogue::print_permissions(manifest::permission_refs())`.

## 12. Tests and CI

- `testutil::platform::Platform` starts a fake `gateway` and `auth` over
  mTLS; build the module with an SVID from `p.ca`, point
  `discovery.static` at `p.discovery()`, mint tokens with `p.token(..)`,
  call the module as the gateway with `p.call(..)` (`tests/module.rs`).
- CI: `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D
  warnings`, `cargo test --all-features`, the go-tangra `docs-lint` action,
  the UI lint, the image (GHCR tags semver + `sha-<short>`, no `latest`),
  and on `v*` tags the go-tangra `catalogue-entry` action, which builds,
  attests (`actions/attest-build-provenance`) and attaches
  `catalogue-entry.json` and `bundle.zip`. Template:
  [`templates/module/.github/workflows/release.yaml`](../templates/module/.github/workflows/release.yaml).
