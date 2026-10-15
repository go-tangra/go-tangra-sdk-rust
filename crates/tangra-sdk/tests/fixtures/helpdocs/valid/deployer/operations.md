---
title: Operate the deployer
summary: Configuration keys and defaults, the service policies the deployer needs from lcm, auth and inventory, and fixes for common start-up and deployment errors.
kind: reference
order: 90
tags: [deployer, operations, configuration, policy, troubleshooting]
audience: operator
---
The deployer runs as `deployersvc` (image `ghcr.io/go-tangra/go-tangra-deployer`).

```sh
deployersvc -config /app/config.yaml             # serve; applies migrations
deployersvc bootstrap -config /app/config.yaml   # apply migrations and exit
deployersvc version
```

At start it enrolls for its SVID `spiffe://<trust domain>/svc/deployer`,
migrates its TimescaleDB schema, serves the module API and `deployer.v1` gRPC,
registers with the gateway and registers its permissions and roles with auth.

## Configuration

The file is YAML. Unknown keys are refused, so a typo stops the service at
start with `config: <file>: ...`. Besides the framework keys (`service_name`,
`trust_domain`, `env`, `identity`, `authz`, `server`, `admin`, `discovery`,
`limits`) the deployer reads:

| Key | Default | Notes |
|---|---|---|
| `db.dsn` | — | required; in production `sslmode=verify-full` (or `verify-ca`) |
| `db.migrate_dsn` | — | owner connection used for migrations |
| `db.max_conns` | 16 | |
| `valkey.addresses` | — | required; the platform event bus |
| `valkey.username`, `valkey.password`, `valkey.ca_file` | — | Valkey user `deployer` over TLS |
| `valkey.allow_plaintext` | false | development only; refused in production |
| `kek.source` | `file` | `file` (with `kek.path`) or `env` (with `kek.env`): the 32-byte key that seals provider credentials |
| `jobs.workers` | 5 | 1–64 |
| `jobs.interval_seconds` | 5 | 1–60, how often workers look for due jobs |
| `jobs.lease_seconds` | 300 | interval–3600, how long a claimed job stays claimed |
| `jobs.retry_delay_seconds` | 60 | 1–3600, first retry delay |
| `jobs.backoff_multiplier` | 2.0 | 1–10, growth of the delay per retry |
| `jobs.job_timeout_seconds` | 300 | 10–3600, one deployment attempt |
| `jobs.cleanup_days` | 30 | 1–3650, job retention |
| `jobs.max_retries` | 3 | 0–20; checked at start, but jobs are currently created with 3 retries |
| `events.enabled` | true | auto-deploy consumer of `certificate.issued` / `certificate.renewed` |
| `gateway.service` | `gateway` | mesh name of the gateway; the only peer allowed to fetch the help pages |
| `gateway.issuer` | — | required, an `https://` origin: the platform token issuer |
| `lcm.service` | `lcm` | where certificates are downloaded from |
| `inventory.service` | empty | set (for example `inventory`) to enable the Inventory agent provider |
| `enroll.*` | — | `enabled`, `enroll_url`, `lcm_grpc`, `tenant_id`, `token_file`, `state_file` for SVID enrollment |
| `limits_deployer.*` | 16 MiB / 16 KiB / 256 | `backup_max_bytes`, `config_max_bytes`, `filter_max_length`; range-checked at start |

Auto-deploy reads the event stream of the tenant named in
`enroll.tenant_id`. The consumer starts at the stream's current end, so events
published while the deployer was down are not replayed.

## Service policies

The deployer's own policy must let the gateway in. The usual rule covers the
browser API, health probes and the help pages (`GET /docs/v1/bundle`):

```yaml
rules:
  - id: gateway-forwards
    from: ["spiffe://<trust domain>/svc/gateway"]
    to: ["deployer"]
    operations: ["GET *", "HEAD *", "POST *", "PUT *"]
    effect: allow
```

Other modules must admit `spiffe://<trust domain>/svc/deployer`:

| Module | Operation | Why |
|---|---|---|
| lcm | `/lcm.v1.Certificates/Download` | fetch certificate, chain and key at deploy time |
| auth | `/auth.v1.Profiles/ListMembers` | address job events to users holding `jobs:read` |
| inventory | `inventory.v1.CertificateDeliveryService` methods | Inventory agent provider; inventory's `cert_delivery.sources` must also list `deployer` |

For the Inventory agent provider the deployer also needs
`discovery.static.inventory` and `inventory: { service: inventory }`.

## Troubleshooting

**The service refuses to start with `config: ...`.** The message names the
key and its allowed range. Common ones: `db.dsn must use sslmode=verify-full`
in production, `gateway.issuer must be an https origin`, `kek.path is
required for kek.source file`.

**The service refuses to start with `help docs: ...`.** The help pages built
into the binary are invalid. This is caught by `tangra-docs lint` in CI; a
build that skips CI must be rebuilt.

**Jobs fail with `certificate fetch failed` and keep retrying.** lcm is
unreachable or its policy does not allow `/lcm.v1.Certificates/Download` for
the deployer. Check the lcm policy and `discovery.static.lcm`.

**Jobs fail with `certificate has no stored private key`.** lcm keeps no private
key for that certificate, and the provider needs one. Reissue the
certificate in lcm so that lcm retains its key. The job is not retried.

**Jobs fail with `credentials unavailable`.** The stored credentials cannot be
opened with the current key-encryption key. Make sure `kek` points at the
same key as when the configuration was saved; otherwise re-enter the
credentials.

**The Jobs page does not update live.** The log shows `deployer: job event
not sent: readers unavailable`: auth is unreachable, or its policy does not
allow `/auth.v1.Profiles/ListMembers`. Events are dropped rather than sent to
the whole tenant; the Jobs page still shows the state on reload. A new grant
of `jobs:read` takes effect within about 30 seconds.

**New certificates are not deployed automatically.** Check that
`events.enabled` is true, that the target has auto-deploy on, a matching
filter and at least one attached configuration, and that the certificate was
issued in the tenant named by `enroll.tenant_id`.

**Role changes are missing in auth.** Look for `auth registration: ...` in
the log. The deployer registers every five minutes; a revoked built-in grant
is withdrawn only by an auth that supports `declares_builtin_grants`.
