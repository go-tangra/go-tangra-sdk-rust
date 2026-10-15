# livestack: the example module against the real core

`livestack.sh` runs `tangra-notes` (`examples/notes`) against the real
go-tangra v4 core services, built from your local checkouts, as native
processes on `127.0.0.1`. It needs no Docker and no root. It then checks the
module path end to end through the real gateway.

| Process | Built from | Role |
|---|---|---|
| `lcmsvc` | go-tangra-lcm-v4 `cmd/lcmsvc` | mesh CA (DB-sealed root), enrolment over HTTPS, renewal over gRPC |
| `authsvc` | go-tangra-auth `cmd/authsvc` | tenants, users, sessions, tokens, permission registration |
| `gatewaysvc` | go-tangra-portal-v4 `cmd/gatewaysvc` | edge (`https://localhost:18443`), module registry, docs index, SSE |
| PostgreSQL 16 | zonky embedded-postgres binaries | one instance; databases `auth`, `gateway`, `lcm`, `openfga` |
| Valkey (TLS) | a `valkey-server` you provide | sessions, registry, the event bus |
| OpenFGA | `go install` of the version the stack runs | auth's relationship store |
| `tangra-notes` | this repository, `--features ui` | the module under test |

The platform sources are exported with `git archive <ref>` into the cache, so
the checkouts are never modified. Each run's data, keys, certificates,
configs, logs and tokens go to `$LS_WORK`. Tokens and passwords are never
printed.

## Run

```sh
export PATH=$HOME/.cargo/bin:$PATH
export NODE_AUTH_TOKEN=$(gh auth token)      # read:packages, for @go-tangra/ui
VALKEY_SERVER=/path/to/valkey-server tools/livestack/livestack.sh all
```

The commands are:

- `up`: builds everything and starts the core. It then signs in the
  operator and creates the test users.
- `check`: runs notes twice, first with a file identity and then with lcm
  enrolment, and runs the checks after each. It prints `PASS`/`FAIL` with
  evidence and exits 1 if any check fails.
- `down`: stops every process the run started. It uses the pid files and
  only stops a process whose command line names the work or cache dir.
- `all`: runs `up`, `check` and `down`. `down` runs even after a failure.
- `clean`: runs `down`, then deletes `$LS_WORK`. `up` refuses to run over a
  previous run's work dir.

A full `all` takes about 6 minutes after the first build. The lcm renewal
check alone waits about 3 minutes; set `LS_RENEWAL=0` to skip it.

### Parameters (environment)

| Variable | Default |
|---|---|
| `PORTAL_REPO`, `AUTH_REPO`, `LCM_REPO` | `../go-tangra-portal-v4`, `../go-tangra-auth`, `../go-tangra-lcm-v4` next to this repository |
| `PORTAL_REF`, `AUTH_REF`, `LCM_REF` | `origin/main` (run `git fetch` in the checkouts first) |
| `LS_WORK` | `$TMPDIR/tangra-livestack` |
| `LS_CACHE` | `~/.cache/tangra-livestack` (built binaries and exported sources; a platform binary is rebuilt when its ref moves) |
| `VALKEY_SERVER` | `valkey-server` on `PATH`; it must be built with TLS |
| `PG_DIR` | a PostgreSQL directory with `bin/`, `lib/`, `share/` and the citext and pg_trgm extensions. Without it, the zonky `embedded-postgres-binaries-linux-amd64` `$PG_VERSION` jar is downloaded from Maven Central |
| `OPENFGA_BIN` | otherwise `go install github.com/openfga/openfga/cmd/openfga@$OPENFGA_VERSION` (`v1.20.0`) |
| `LS_UI` | `1`: `npm ci && npm run build` in `examples/notes/ui`. With `0`, an existing `ui/dist` is used |
| `LS_RENEWAL` | `1`: also prove gRPC renewal |
| `P_*` | the ports (see the top of the script) |

You also need `go`, `cargo`, `node`/`npm`, `openssl`, `curl`, `python3` and
`unzip`/`xz` (the latter two only for the PostgreSQL download).

## What the setup does

The setup follows the platform's own stack (go-tangra
`deploy/stack/compose.yaml`, `ENROLLMENT.md`), translated to native
processes:

1. **PostgreSQL** starts with a **TimescaleDB shim** (`timescaledb-shim/`).
   It is not TimescaleDB: it provides the two functions the core migrations
   call (`create_hypertable`, `add_retention_policy`) as no-ops, so the
   tables stay plain tables. Everything else in the migrations is stock
   PostgreSQL.
2. `lcmsvc bootstrap` creates the mesh root and file SVIDs for `gateway`,
   `auth` and `notes`. lcm then serves with a self-issued identity.
3. `authsvc bootstrap` seeds the platform tenant, the built-in roles, the
   signing key and the operator invitation. Email goes to the log sink.
4. `gatewaysvc bootstrap -allow` writes the route allow-list. This is what a
   catalogue install grants: `spiffe://example.org/svc/notes` gets
   `/api/notes` and the name `notes`.
5. The gateway edge uses a certificate from a local CA. The module trusts
   that CA through `SSL_CERT_FILE`, as it would trust a public CA in
   production. Valkey runs TLS-only with ACL users, like production.
6. Users sign in through the gateway's real browser flow: invitation accept
   (`POST /api/v1/invitations/accept` with the CSRF cookie and header), which
   leaves a `__Host-session` cookie. The users are:
   - `op`: the platform operator and owner of the platform tenant;
   - `auditor`: platform tenant, role `auditor` (`notes:read` only);
   - `viewer`: platform tenant, role `m.lcm.viewer` (no notes permission);
   - `globex`: owner of a second tenant, created through
     `POST /api/v1/operator/tenants`.

## What `check` proves

Phase A uses `identity.provider: file`. Phase B uses lcm enrolment. The
enrolment token is minted with `POST /gateway/v1/ops/enrollment-tokens`,
which calls `auth.v1.Enrollment/MintEnrollmentToken`. The module enrols at
`https://localhost:18443/api/lcm/v1/enroll` through the gateway.

Checks in both phases:

- **Registration:**
  - a `registration_accepted` audit row;
  - the stored manifest (`known_modules`);
  - `ops/registrations` shows notes `active` with its routes and docs digest.
- **Help docs:**
  - the gateway logs `docs: indexed` with a page count;
  - a `module_docs_state` row exists;
  - docs search finds the notes pages.
- **Auth registration:** the permissions, the module roles and the built-in
  grants appear in auth's tables.
- **API through the gateway:**
  - create (201) and list (200) work;
  - anonymous calls get 401;
  - a user without the permission gets 403, and `notes:read` without
    `notes:write` gets 403 on create;
  - tenant isolation: the other tenant's list excludes the note, and a read
    by ID returns 404.
- **UI remote:** `/m/notes/mf-manifest.json` and the remote entry are served
  through the gateway.
- **Events:** `notes.created` reaches the gateway SSE stream of a user in the
  same tenant, and not the other tenant's stream.
- **Deregistration:** shutdown produces `registration_withdrawn`, and notes
  leaves `ops/registrations`.

Phase B also checks:

- **State file:** written with mode 0600. A restart reuses the persisted
  SVID; the single-use token is already spent.
- **gRPC renewal:**
  1. A 3-minute SVID from the same root is planted as the state.
  2. The module renews it over mTLS gRPC (`/lcm.v1.Enrollment/Enroll`; lcm
     logs the call).
  3. API calls through the gateway still work after the old SVID has
     expired.

## Known platform behaviour (not SDK issues)

- Built-in grants (owner, admin and so on) reach a tenant only when a module
  registers its permissions. A tenant created after the module registered
  gets them at the module's next registration: within 5 minutes, or at a
  restart. The Go modules behave the same. The setup creates every tenant
  before notes starts.
- The platform tenant has no `member` role, so auth logs `built-in grant
  skipped ... role_missing` for every module.
- lcm issues enrolled SVIDs for 90 days (`issue.DefaultValiditySeconds`).
  Nothing configures a shorter lifetime, so the renewal check plants a short
  SVID from `lcmsvc bootstrap`.
- `openssl req -x509`, as the platform stack's `edge-cert-init` uses it,
  makes a CA certificate. rustls refuses a CA certificate as a server's end
  entity (`CaUsedAsEndEntity`); Go accepts it when it sits in the root pool.
  A Rust module can therefore not trust such a dev edge certificate directly
  (the dev stack sets `insecure: true`). This setup uses a CA and a leaf
  instead.
