---
title: Operate notes
summary: Running the service, its configuration keys, the policies it needs and fixes for common start-up errors.
kind: reference
order: 90
tags: [notes, operations, configuration, troubleshooting]
audience: operator
---
The module runs as `tangra-notes` (image `ghcr.io/go-tangra/tangra-notes`).

```sh
tangra-notes -config /app/config.yaml                 # serve
tangra-notes bootstrap -config /app/config.yaml       # apply the schema and exit
tangra-notes --healthcheck -config /app/config.yaml   # exit 0 when ready
tangra-notes version
```

At start it enrolls for its SVID `spiffe://<trust domain>/svc/notes`,
registers with the gateway (manifest and help digest) and registers its
permissions and roles with auth.

## Configuration

The file is YAML. Unknown keys are refused, so a typo stops the service with
`config: <file>: ...`. Besides the framework keys (`service_name`,
`trust_domain`, `env`, `identity`, `authz`, `server`, `admin`, `discovery`,
`limits`) notes reads:

| Key | Default | Notes |
|---|---|---|
| `gateway.service` | `gateway` | the only peer served the help bundle |
| `gateway.issuer` | — | required; `https` origin of platform tokens |
| `events.enabled` | `true` | publish `notes.created`; needs `valkey` |
| `valkey.addresses` | — | `host:port`; TLS unless `allow_plaintext` (refused in production) |
| `enroll.*` | off | lcm network enrolment (`enroll_url`, `lcm_grpc`, `tenant_id`, `token_file`, `state_file`) |
| `limits_notes.max_notes_per_tenant` | `10000` | 1–1000000 |

## Policies

The module's own policy admits only the gateway. On the core, auth must
allow `spiffe://<trust domain>/svc/notes` to call
`auth.v1.Authorization/RegisterPermissions`, `Authorization/Check`,
`Keys/List` and `Sessions/RevokedSince`.

## Troubleshooting

| Log line | Fix |
|---|---|
| `gateway lease ... prefix_not_granted` | install the module from the catalogue so the gateway grants `/api/notes` |
| `auth registration failed; retrying` | auth unreachable or refusing: check `discovery.static.auth` and auth's policy |
| `notes: event bus: ...` at start | Valkey unreachable or the `notes` user refused |
