#!/usr/bin/env bash
# livestack: run the example module (tangra-notes) against the REAL go-tangra
# v4 core - lcm (CA + enrolment), auth, gateway - as native processes on
# 127.0.0.1, with Postgres, Valkey (TLS) and OpenFGA beside them, then check
# the module path end to end through the gateway. No Docker, no root.
#
#   tools/livestack/livestack.sh up      build + start the core, seed users
#   tools/livestack/livestack.sh check   run notes (file identity, then lcm
#                                        enrolment) and the checks
#   tools/livestack/livestack.sh down    stop every process this run started
#   tools/livestack/livestack.sh all     up + check + down (exit 1 on a FAIL)
#   tools/livestack/livestack.sh clean   down, then delete the work dir
#
# Everything generated for a run (data, keys, certificates, configs, logs,
# tokens) lives in $LS_WORK; built binaries are cached in $LS_CACHE. Nothing
# is written to the platform checkouts: their sources are exported with
# `git archive`. See README.md.
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
SDK=$(cd "$HERE/../.." && pwd)
GT=$(cd "$SDK/.." && pwd)

# --- parameters -------------------------------------------------------------
: "${LS_WORK:=${TMPDIR:-/tmp}/tangra-livestack}"
: "${LS_CACHE:=${XDG_CACHE_HOME:-$HOME/.cache}/tangra-livestack}"
: "${PORTAL_REPO:=$GT/go-tangra-portal-v4}"
: "${AUTH_REPO:=$GT/go-tangra-auth}"
: "${LCM_REPO:=$GT/go-tangra-lcm-v4}"
: "${PORTAL_REF:=origin/main}"
: "${AUTH_REF:=origin/main}"
: "${LCM_REF:=origin/main}"
: "${OPENFGA_VERSION:=v1.20.0}"   # what the platform stack runs
: "${PG_VERSION:=16.9.0}"         # zonky embedded-postgres binaries
: "${LS_RENEWAL:=1}"              # 1: also prove lcm gRPC renewal (~3 min)
: "${LS_UI:=1}"                   # 1: npm ci + npm run build the notes UI
: "${CARGO:=$(command -v cargo || echo "$HOME/.cargo/bin/cargo")}"
# Hooks for another module's runner that sources this script (see README,
# "Another module"): LS_NOTES=0 skips building notes; LS_EXTRA_SERVICES
# (space-separated names) get a file SVID from lcm bootstrap and a Valkey
# ACL user, and are stopped by down; LS_EXTRA_ALLOW (space-separated
# `spiffe-id=prefixes;names`) adds gateway route allow-list entries;
# LS_EXTRA_DBS (space-separated) creates each database with a <db>_app
# LOGIN NOBYPASSRLS role (password dev), as a module bundle's init-db.sh.
: "${LS_NOTES:=1}" "${LS_EXTRA_SERVICES:=}" "${LS_EXTRA_ALLOW:=}" "${LS_EXTRA_DBS:=}"
# Optional prebuilt binaries: PG_DIR (bin/, lib/, share/ of PostgreSQL >= 14
# with citext and pg_trgm), VALKEY_SERVER (TLS-capable), OPENFGA_BIN.

# Ports (all on 127.0.0.1; override any of them).
: "${P_PG:=56432}" "${P_VALKEY:=56379}" "${P_FGA_HTTP:=58080}" "${P_FGA_GRPC:=58081}"
: "${P_LCM_GRPC:=19945}" "${P_LCM_HTTP:=19946}" "${P_LCM_ENROLL:=19947}" "${P_LCM_ADMIN:=19591}"
: "${P_AUTH_GRPC:=19543}" "${P_AUTH_HTTP:=19544}" "${P_AUTH_ADMIN:=19190}"
: "${P_GW_GRPC:=19643}" "${P_GW_EDGE:=18443}" "${P_GW_ADMIN:=19290}"
: "${P_NOTES_GRPC:=19965}" "${P_NOTES_HTTP:=19966}" "${P_NOTES_ADMIN:=19695}"

TD=example.org
MESH_TENANT=00000000-0000-0000-0000-000000000001
W=$LS_WORK
G=https://localhost:$P_GW_EDGE
PGURL=postgres://postgres:dev@127.0.0.1:$P_PG
C=$LS_CACHE
BIN=$C/bin

log() { printf '\033[1m[livestack]\033[0m %s\n' "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

# --- process control: every process gets a pid file; down kills only those --
start() { # name logfile cmd...
  local name=$1 logf=$2; shift 2
  "$@" >>"$logf" 2>&1 &
  echo $! >"$W/run/$name.pid"
  log "started $name (pid $!)"
}
stop() { # name
  local f=$W/run/$1.pid p
  [ -f "$f" ] || return 0
  p=$(cat "$f")
  # Only a process whose command line still names this run's work dir.
  if kill -0 "$p" 2>/dev/null && tr '\0' ' ' <"/proc/$p/cmdline" | grep -qF -e "$W" -e "$C"; then
    kill -TERM "$p"
    for _ in $(seq 1 40); do kill -0 "$p" 2>/dev/null || break; sleep 0.25; done
    kill -0 "$p" 2>/dev/null && { log "$1 ignored SIGTERM; killing"; kill -KILL "$p"; }
    log "stopped $1"
  fi
  rm -f "$f"
}
wait_http() { # url what [tries]
  for _ in $(seq 1 "${3:-60}"); do
    curl -s -o /dev/null --max-time 2 "$1" && return 0
    sleep 1
  done
  die "$2 did not come up ($1)"
}
wait_log() { # file pattern what [seconds]
  for _ in $(seq 1 "${4:-60}"); do
    grep -qE "$2" "$1" 2>/dev/null && return 0
    sleep 1
  done
  die "$3: no '$2' in $1"
}

sql() { "$BIN/lshelper" "$PGURL/$1" "$2"; }
pyget() { python3 -I -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1], {'d': d}))" "$1"; }

# --- users: browser calls through the gateway edge (cookie jar per user) ----
jar() { echo "$W/users/$1.jar"; }
csrf() { awk '$6=="__Host-csrf"{print $7}' "$(jar "$1")" 2>/dev/null; }
# req user METHOD path [json] -> prints body, then the status on the last line
req() {
  local u=$1 m=$2 p=$3 d=${4:-}
  local args=(-s --cacert "$W/edge/ca.crt" -b "$(jar "$u")" -c "$(jar "$u")" -X "$m" -w '\n%{http_code}')
  if [ "$m" != GET ]; then
    args+=(-H "Origin: $G" -H "X-CSRF-Token: $(csrf "$u")" -H 'Content-Type: application/json' -d "$d")
  fi
  curl "${args[@]}" "$G$p"
}
code() { tail -n1; }
body() { sed '$d'; }

# ============================================================================
build() {
  mkdir -p "$C"/{src,bin} "$W"/{run,logs,cfg,certs,edge,valkey-tls,users,tokens,notes-state}
  chmod 700 "$W/tokens" "$W/notes-state"
  : >"$W/VERSIONS"
  for spec in "portal:$PORTAL_REPO:$PORTAL_REF:./cmd/gatewaysvc" "auth:$AUTH_REPO:$AUTH_REF:./cmd/authsvc" "lcm:$LCM_REPO:$LCM_REF:./cmd/lcmsvc"; do
    IFS=: read -r n repo ref cmd <<<"$spec"
    [ -d "$repo/.git" ] || die "$n: $repo is not a git checkout (set ${n^^}_REPO)"
    local rev; rev=$(git -C "$repo" rev-parse --short "$ref")
    echo "$n $(basename "$repo") $ref $rev" >>"$W/VERSIONS"
    if [ ! -x "$BIN/$(basename "$cmd")" ] || [ "$(cat "$C/src/$n.rev" 2>/dev/null)" != "$rev" ]; then
      log "building $n ($ref = $rev)"
      rm -rf "$C/src/$n" && mkdir -p "$C/src/$n"
      git -C "$repo" archive "$ref" | tar -x -C "$C/src/$n"
      (cd "$C/src/$n" && GOWORK=off GOFLAGS=-mod=mod go build -buildvcs=false -o "$BIN/$(basename "$cmd")" "$cmd")
      echo "$rev" >"$C/src/$n.rev"
    fi
  done
  log "building lshelper"
  (cd "$HERE/lshelper" && GOWORK=off go build -buildvcs=false -o "$BIN/lshelper" .)
  if [ -n "${OPENFGA_BIN:-}" ]; then ln -sf "$OPENFGA_BIN" "$BIN/openfga"; fi
  if [ ! -x "$BIN/openfga" ]; then
    log "building openfga $OPENFGA_VERSION"
    GOBIN=$BIN GOWORK=off GOFLAGS= go install "github.com/openfga/openfga/cmd/openfga@$OPENFGA_VERSION"
  fi
  : "${VALKEY_SERVER:=$(command -v valkey-server || true)}"
  [ -x "$VALKEY_SERVER" ] || die "set VALKEY_SERVER to a TLS-capable valkey-server"
  ln -sf "$VALKEY_SERVER" "$BIN/valkey-server"
  if [ ! -x "$C/pg/bin/postgres" ]; then
    if [ -n "${PG_DIR:-}" ]; then
      cp -a "$PG_DIR" "$C/pg"
    else
      log "downloading PostgreSQL $PG_VERSION (zonky embedded-postgres binaries)"
      local jar=$C/pg.jar
      curl -sfL -o "$jar" "https://repo1.maven.org/maven2/io/zonky/test/postgres/embedded-postgres-binaries-linux-amd64/$PG_VERSION/embedded-postgres-binaries-linux-amd64-$PG_VERSION.jar"
      mkdir -p "$C/pg" && unzip -p "$jar" '*.txz' | tar -xJ -C "$C/pg" && rm -f "$jar"
    fi
  fi
  # The platform migrations call TimescaleDB's create_hypertable and
  # add_retention_policy; this shim extension makes them plain tables.
  local ext=$C/pg/share/postgresql/extension
  cp "$HERE/timescaledb-shim/timescaledb.control" "$HERE/timescaledb-shim/timescaledb--0.0.1.sql" "$ext/"

  [ "$LS_NOTES" = 1 ] && build_notes
  echo "sdk go-tangra-sdk-rust HEAD $(git -C "$SDK" rev-parse --short HEAD)$(git -C "$SDK" diff --quiet HEAD -- crates examples || echo '+dirty')" >>"$W/VERSIONS"
}

build_notes() {
  log "building tangra-notes (features ui)"
  if [ "$LS_UI" = 1 ]; then
    [ -n "${NODE_AUTH_TOKEN:-}" ] || die "LS_UI=1 needs NODE_AUTH_TOKEN (read:packages) for @go-tangra/ui"
    (cd "$SDK/examples/notes/ui" && npm ci --no-audit --no-fund && npm run build) >"$W/logs/ui-build.log" 2>&1 \
      || die "UI build failed (see $W/logs/ui-build.log)"
  fi
  [ -f "$SDK/examples/notes/ui/dist/mf-manifest.json" ] || die "examples/notes/ui/dist is missing (run with LS_UI=1)"
  (cd "$SDK" && "$CARGO" build -q -p tangra-notes --features ui)
  ln -sf "$SDK/target/debug/tangra-notes" "$BIN/tangra-notes"
}

certs() {
  # Gateway edge: a local CA and a leaf (not a self-signed CA cert: rustls,
  # unlike Go, refuses a CA certificate as an end entity).
  local e=$W/edge v=$W/valkey-tls
  for d in "$e:localhost:DNS:localhost,IP:127.0.0.1" "$v:127.0.0.1:DNS:localhost,IP:127.0.0.1"; do
    IFS=: read -r dir cn sans <<<"$d"
    [ -s "$dir/tls.crt" ] && continue
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$dir/ca.key" -out "$dir/ca.crt" -days 30 \
      -subj "/CN=livestack $(basename "$dir") CA" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$dir/tls.key" -out "$dir/tls.csr" -subj "/CN=$cn" 2>/dev/null
    printf 'subjectAltName=%s\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature\nbasicConstraints=critical,CA:FALSE\n' "$sans" >"$dir/leaf.ext"
    openssl x509 -req -in "$dir/tls.csr" -CA "$dir/ca.crt" -CAkey "$dir/ca.key" -CAcreateserial -days 30 -extfile "$dir/leaf.ext" -out "$dir/tls.crt" 2>/dev/null
    chmod 600 "$dir"/*.key; rm -f "$dir/tls.csr" "$dir/ca.srl"
  done
  # Development KEKs (32 random bytes, base64), generated per run.
  for k in auth lcm; do [ -s "$W/$k.kek" ] || (umask 077; head -c32 /dev/urandom | base64 >"$W/$k.kek"); done
}

configs() {
  local vk="valkey: { addresses: [\"127.0.0.1:$P_VALKEY\"], username: %s, password: dev, ca_file: $W/valkey-tls/ca.crt }"
  cat >"$W/cfg/lcm.yaml" <<EOF
service_name: lcm
trust_domain: $TD
env: dev
identity: { provider: provided }   # lcm self-issues from its DB-sealed mesh root
authz: { source: file, path: $C/src/lcm/deploy/policy.yaml }
server: { grpc_addr: 127.0.0.1:$P_LCM_GRPC, http_addr: 127.0.0.1:$P_LCM_HTTP }
admin: { addr: 127.0.0.1:$P_LCM_ADMIN }
discovery: { static: { gateway: ["127.0.0.1:$P_GW_GRPC"], auth: ["127.0.0.1:$P_AUTH_GRPC"] } }
limits: { max_request_bytes: 16842752 }
limits_lcm: { backup_max_bytes: 16777216, csr_max_bytes: 16384, webhook_max_bytes: 65536, streams_per_user: 5, streams_per_tenant: 2000, replay_window_seconds: 300 }
db:
  dsn: postgres://lcm_app:dev@127.0.0.1:$P_PG/lcm?sslmode=disable
  migrate_dsn: $PGURL/lcm?sslmode=disable
$(printf "$vk" lcm)
kek: { source: file, path: $W/lcm.kek }
renewal: { interval_seconds: 15, lease_seconds: 60, workers: 4, short_lived_fraction: 0.5, long_lived_days: 30 }
gateway: { service: gateway, issuer: $G }
acme: { allow_plaintext_dns: true }
enroll_listener: 127.0.0.1:$P_LCM_ENROLL
EOF
  cat >"$W/cfg/auth.yaml" <<EOF
service_name: auth
trust_domain: $TD
env: dev
identity: { provider: file, file: { cert: $W/certs/auth.pem, key: $W/certs/auth.key, bundle: $W/certs/ca.pem } }
authz: { source: file, path: $C/src/auth/deploy/policy.yaml }
server: { grpc_addr: 127.0.0.1:$P_AUTH_GRPC, http_addr: 127.0.0.1:$P_AUTH_HTTP }
admin: { addr: 127.0.0.1:$P_AUTH_ADMIN }
discovery: { static: { gateway: ["127.0.0.1:$P_GW_GRPC"] } }
gateway: { enabled: true, service: gateway }
issuer: $G
db:
  dsn: postgres://auth_app:dev@127.0.0.1:$P_PG/auth?sslmode=disable
  migrate_dsn: $PGURL/auth?sslmode=disable
$(printf "$vk" auth)
openfga: { url: "http://127.0.0.1:$P_FGA_HTTP", preshared_key: dev-openfga-key, allow_plaintext: true }
kek: { source: file, path: $W/auth.kek }
email: { transport: log }   # invitation links go to the log
limits: { max_request_bytes: 2162688 }
EOF
  cat >"$W/cfg/gateway.yaml" <<EOF
service_name: gateway
trust_domain: $TD
env: dev
identity: { provider: file, file: { cert: $W/certs/gateway.pem, key: $W/certs/gateway.key, bundle: $W/certs/ca.pem } }
authz: { source: file, path: $C/src/portal/deploy/policy.yaml }
server: { grpc_addr: 127.0.0.1:$P_GW_GRPC }
admin: { addr: 127.0.0.1:$P_GW_ADMIN }
discovery: { static: { auth: ["127.0.0.1:$P_AUTH_GRPC"] } }
edge:
  addr: 127.0.0.1:$P_GW_EDGE
  cert_file: $W/edge/tls.crt
  key_file: $W/edge/tls.key
  allowed_origins: ["$G"]
  rate_limit: { per_second: 200, burst: 400 }
public_origin: $G
db:
  dsn: postgres://gateway_app:dev@127.0.0.1:$P_PG/gateway?sslmode=disable
  migrate_dsn: $PGURL/gateway?sslmode=disable
$(printf "$vk" gateway)
auth: { service: auth, issuer: $G, audience: gateway }
leases: { ttl: 30s, renew: 10s }
forward: { body_bytes: 1048576, streams_per_client: 32, stream_max: 10m, module_timeout: 30s }
operators: { roles: [operator], admin_roles: [owner, admin] }
limits: { max_request_bytes: 16842752 }
EOF
  sed "s/\${TRUST_DOMAIN}/$TD/g" "$SDK/examples/notes/deploy/bundle/policy.yaml" >"$W/cfg/notes-policy.yaml"
  for mode in file lcm; do
    {
      echo "service_name: notes"
      echo "trust_domain: $TD"
      echo "env: dev"
      if [ $mode = file ]; then
        echo "identity: { provider: file, file: { cert: $W/certs/notes.pem, key: $W/certs/notes.key, bundle: $W/certs/ca.pem } }"
      else
        echo "identity: { provider: provided }"
        echo "enroll:"
        echo "  enabled: true"
        echo "  enroll_url: $G/api/lcm/v1/enroll   # through the gateway edge, as LCM_ENROLL_URL"
        echo "  lcm_grpc: 127.0.0.1:$P_LCM_GRPC"
        echo "  tenant_id: \"$MESH_TENANT\""
        echo "  token_file: $W/tokens/notes.token"
        echo "  state_file: $W/notes-state/svid.json"
      fi
      echo "authz: { source: file, path: $W/cfg/notes-policy.yaml }"
      echo "server: { grpc_addr: 127.0.0.1:$P_NOTES_GRPC, http_addr: 127.0.0.1:$P_NOTES_HTTP }"
      echo "admin: { addr: 127.0.0.1:$P_NOTES_ADMIN }"
      echo "discovery: { static: { gateway: [\"127.0.0.1:$P_GW_GRPC\"], auth: [\"127.0.0.1:$P_AUTH_GRPC\"], lcm: [\"127.0.0.1:$P_LCM_GRPC\"] } }"
      printf "$vk\n" notes
      echo "events: { enabled: true }"
      echo "gateway: { service: gateway, issuer: $G }"
    } >"$W/cfg/notes-$mode.yaml"
  done
}

infra() {
  if [ ! -d "$W/pgdata" ]; then
    "$C/pg/bin/initdb" -D "$W/pgdata" -U postgres --auth=trust -E UTF8 >"$W/logs/initdb.log"
  fi
  # No unix socket: the work dir path can exceed the 107-byte socket limit.
  "$C/pg/bin/pg_ctl" -D "$W/pgdata" -l "$W/logs/postgres.log" -w \
    -o "-p $P_PG -c listen_addresses=127.0.0.1 -c unix_socket_directories=''" start >/dev/null
  log "postgres on 127.0.0.1:$P_PG"
  if [ -z "$(sql postgres "select 1 from pg_database where datname='gateway'")" ]; then
    sql postgres "ALTER ROLE postgres PASSWORD 'dev'" >/dev/null
    for db in openfga auth gateway lcm; do sql postgres "CREATE DATABASE $db" >/dev/null; done
    for db in auth gateway lcm; do
      sql "$db" "CREATE EXTENSION IF NOT EXISTS timescaledb; CREATE EXTENSION IF NOT EXISTS citext;
        CREATE ROLE ${db}_app LOGIN PASSWORD 'dev' NOBYPASSRLS; GRANT CONNECT ON DATABASE $db TO ${db}_app" >/dev/null
    done
    for db in $LS_EXTRA_DBS; do
      sql postgres "CREATE DATABASE $db" >/dev/null
      sql "$db" "CREATE ROLE ${db}_app LOGIN PASSWORD 'dev' NOBYPASSRLS; GRANT CONNECT ON DATABASE $db TO ${db}_app" >/dev/null
      log "database $db (role ${db}_app NOBYPASSRLS)"
    done
  fi
  local users=()
  for u in gateway auth lcm notes $LS_EXTRA_SERVICES; do users+=(--user "$u" on '>dev' '~*' '&*' '+@all'); done
  start valkey "$W/logs/valkey.log" "$BIN/valkey-server" --port 0 --bind 127.0.0.1 --tls-port "$P_VALKEY" \
    --tls-cert-file "$W/valkey-tls/tls.crt" --tls-key-file "$W/valkey-tls/tls.key" --tls-ca-cert-file "$W/valkey-tls/ca.crt" \
    --tls-auth-clients no --dir "$W" --save '' --appendonly no --requirepass dev "${users[@]}"
  local fga="postgres://postgres:dev@127.0.0.1:$P_PG/openfga?sslmode=disable"
  "$BIN/openfga" migrate --datastore-engine postgres --datastore-uri "$fga" >>"$W/logs/openfga.log" 2>&1
  start openfga "$W/logs/openfga.log" "$BIN/openfga" run --datastore-engine postgres --datastore-uri "$fga" \
    --authn-method preshared --authn-preshared-keys dev-openfga-key --http-addr "127.0.0.1:$P_FGA_HTTP" \
    --grpc-addr "127.0.0.1:$P_FGA_GRPC" --playground-enabled=false --metrics-enabled=false --log-format json
  wait_http "http://127.0.0.1:$P_FGA_HTTP/healthz" openfga
}

core() {
  cd "$W"
  # lcm bootstrap: the DB-sealed mesh root + file SVIDs (gateway, auth, and
  # notes for the file-identity run), all under the one root lcm serves.
  "$BIN/lcmsvc" bootstrap -config "$W/cfg/lcm.yaml" -out "$W/certs" -services "gateway,auth,notes${LS_EXTRA_SERVICES:+,${LS_EXTRA_SERVICES// /,}}" -ttl 12h >"$W/logs/lcm-bootstrap.log" 2>&1
  start lcm "$W/logs/lcm.log" "$BIN/lcmsvc" -config "$W/cfg/lcm.yaml"
  wait_http "http://127.0.0.1:$P_LCM_ADMIN/readyz" lcm
  # auth bootstrap: platform tenant, roles, signing key, operator invitation.
  "$BIN/authsvc" bootstrap -config "$W/cfg/auth.yaml" -operator-email operator@example.org >"$W/logs/auth-bootstrap.log" 2>&1
  start auth "$W/logs/auth.log" "$BIN/authsvc" -config "$W/cfg/auth.yaml"
  wait_http "http://127.0.0.1:$P_AUTH_ADMIN/readyz" auth
  # gateway bootstrap: the route allow-list (what a catalogue install grants).
  local extra=() x
  for x in $LS_EXTRA_ALLOW; do extra+=(-allow "$x"); done
  "$BIN/gatewaysvc" bootstrap -config "$W/cfg/gateway.yaml" \
    -allow "spiffe://$TD/svc/auth=/api/v1,/authorize,/.well-known,/console;auth" \
    -allow "spiffe://$TD/svc/lcm=/api/lcm;lcm" \
    -allow "spiffe://$TD/svc/notes=/api/notes;notes" \
    "${extra[@]}" >"$W/logs/gateway-bootstrap.log" 2>&1
  start gateway "$W/logs/gateway.log" "$BIN/gatewaysvc" -config "$W/cfg/gateway.yaml"
  wait_http "http://127.0.0.1:$P_GW_ADMIN/readyz" gateway
  wait_log "$W/logs/auth.log" '"msg":"gateway lease","registered":true' "auth registration" 60
  wait_log "$W/logs/lcm.log" '"msg":"gateway lease","registered":true' "lcm registration" 60
}

invite_link() { # email -> token (waits for the auth outbox to deliver)
  local t=""
  for _ in $(seq 1 45); do
    t=$(grep -h '"msg":"email (dev sink)"' "$W/logs/auth-bootstrap.log" "$W/logs/auth.log" 2>/dev/null | grep "\"to\":\"$1\"" \
      | grep -oE 'accept\?token=[A-Za-z0-9_-]+' | tail -1 | cut -d= -f2) || true
    [ -n "$t" ] && { echo "$t"; return; }
    sleep 1
  done
  die "no invitation email for $1"
}
accept() { # user email
  curl -s --cacert "$W/edge/ca.crt" -c "$(jar "$1")" -o /dev/null "$G/gateway/v1/me" # CSRF cookie
  local r; r=$(req "$1" POST /api/v1/invitations/accept "{\"token\":\"$(invite_link "$2")\",\"display_name\":\"$1\",\"password\":\"Livestack-$1-$RANDOM-Pw!\"}")
  [ "$(code <<<"$r")" = 200 ] || die "accept $1: $r"
  log "user $1 ($2) signed in"
}
users() {
  accept op operator@example.org
  local r; r=$(req op POST /api/v1/operator/tenants '{"slug":"globex","display_name":"Globex","owner_email":"owner@globex.test"}')
  [ "$(code <<<"$r")" = 201 ] || die "create tenant: $r"
  accept globex owner@globex.test
  local roles; roles=$(req op GET /api/v1/admin/roles | body)
  for spec in auditor:auditor m.lcm.viewer:viewer; do
    IFS=: read -r role u <<<"$spec"
    local id; id=$(pyget "[r['id'] for r in d if r['slug']=='$role'][0]" <<<"$roles")
    r=$(req op POST /api/v1/admin/invitations "{\"email\":\"$u@example.org\",\"role_ids\":[\"$id\"]}")
    [ "$(code <<<"$r")" = 202 ] || die "invite $u: $r"
  done
  accept auditor auditor@example.org
  accept viewer viewer@example.org
}

up() {
  [ -e "$W/pgdata" ] && die "$W holds a previous run; run '$0 clean' (or set LS_WORK)"
  build
  certs
  configs
  infra
  core
  users
  log "core up; work dir $W"
  cat "$W/VERSIONS" >&2
}

# ============================================================================
FAILS=0
ok() { printf '  \033[32mPASS\033[0m %s\n' "$*"; }
ko() { printf '  \033[31mFAIL\033[0m %s\n' "$*"; FAILS=$((FAILS + 1)); }
expect() { # what expected-status response
  local c; c=$(code <<<"$3")
  if [ "$c" = "$2" ]; then ok "$1 -> $c $(body <<<"$3" | head -c 140)"; else ko "$1: want $2, got $c $(body <<<"$3" | head -c 300)"; fi
}

notes_up() { # mode logfile
  start notes "$2" env SSL_CERT_FILE="$W/edge/ca.crt" "$BIN/tangra-notes" -config "$W/cfg/notes-$1.yaml"
  wait_http "http://127.0.0.1:$P_NOTES_ADMIN/readyz" "notes ($1)" 90
  wait_log "$2" '"msg":"registered with gateway"' "notes registration" 60
}
notes_down() { stop notes; }

check_registration() {
  local acc=0
  for _ in $(seq 1 20); do # the audit writer is asynchronous
    acc=$(sql gateway "select count(*) n from gateway_audit_events where module='notes' and event_type='registration_accepted' and ts >= '$T0'" | pyget "d['n']")
    [ "$acc" -ge 1 ] && break
    sleep 0.5
  done
  [ "$acc" -ge 1 ] && ok "gateway audit: registration_accepted for notes ($acc)" || ko "no registration_accepted row"
  local km; km=$(sql gateway "select last_version, manifest_hash, identity from known_modules where module='notes'")
  [ -n "$km" ] && ok "known_modules (manifest stored): $km" || ko "notes missing from known_modules"
  local regs; regs=$(req op GET /gateway/v1/ops/registrations | body)
  local st; st=$(pyget "[(i['state'], i['manifest']['routes'], i['manifest']['permissions'], i['docs_digests']) for i in d['items'] if i['module']=='notes']" <<<"$regs")
  [[ $st == *active* ]] && ok "ops/registrations: notes $st" || ko "ops/registrations: $st"
  # The gateway indexes a digest once; a re-registration with the same
  # digest does not log it again.
  local dl; dl=$(grep -h '"msg":"docs: indexed","module":"notes"' "$W/logs/gateway.log" | tail -1)
  [ -n "$dl" ] && ok "gateway log: $(cut -c1-220 <<<"$dl")" || ko "no 'docs: indexed' for notes in the gateway log"
  local ds; ds=$(sql gateway "select module, page_count, digest, error from module_docs_state where module='notes'")
  [[ $ds == *'"page_count":'[1-9]* ]] && ok "module_docs_state: $ds" || ko "module_docs_state: $ds"
  local perms; perms=$(sql auth "select string_agg(resource||':'||action, ',' order by action) p from module_permissions where module='notes' and retired_at is null" | pyget "d['p']")
  [ "$perms" = "notes:admin,notes:read,notes:write" ] && ok "auth module_permissions: $perms" || ko "auth module_permissions: $perms"
  local roles; roles=$(sql auth "select string_agg(slug, ',' order by slug) s from module_role_defs where module='notes'" | pyget "d['s']")
  [ "$roles" = "editor,moderator" ] && ok "auth module roles: $roles" || ko "auth module roles: $roles"
  local grant; grant=$(sql auth "select string_agg(distinct r.slug||'='||rp.action, ',') g from role_permissions rp join roles r on r.id=rp.role_id where rp.module='notes' and rp.tenant_id='$MESH_TENANT' and r.slug in ('owner','auditor')" | pyget "d['g']")
  [[ $grant == *owner=write* && $grant == *auditor=read* && $grant != *auditor=write* ]] && ok "built-in grants: $grant" || ko "built-in grants: $grant"
}

check_api() {
  local r id
  r=$(req op POST /api/notes/v1/notes '{"title":"livestack note","body":"through the real gateway"}'); expect "owner creates a note" 201 "$r"
  id=$(body <<<"$r" | pyget "d['id']")
  r=$(req op GET /api/notes/v1/notes); expect "owner lists notes" 200 "$r"
  [[ $(body <<<"$r") == *"$id"* ]] && ok "list contains the new note" || ko "list misses $id"
  r=$(curl -s --cacert "$W/edge/ca.crt" -w '\n%{http_code}' "$G/api/notes/v1/notes"); expect "anonymous list" 401 "$r"
  r=$(req viewer GET /api/notes/v1/notes); expect "user without notes permission lists" 403 "$r"
  r=$(req auditor GET /api/notes/v1/notes); expect "auditor (notes:read) lists" 200 "$r"
  r=$(req auditor POST /api/notes/v1/notes '{"title":"nope"}'); expect "auditor (no notes:write) creates" 403 "$r"
  r=$(req globex POST /api/notes/v1/notes '{"title":"globex only"}'); expect "other tenant's owner creates" 201 "$r"
  r=$(req globex GET /api/notes/v1/notes)
  [[ $(body <<<"$r") == *"globex only"* && $(body <<<"$r") != *"$id"* ]] && ok "other tenant lists only its own notes" || ko "tenant isolation (list): $r"
  r=$(req globex GET "/api/notes/v1/notes/$id"); expect "other tenant reads this tenant's note" 404 "$r"
  r=$(req op GET /api/notes/v1/notes)
  [[ $(body <<<"$r") != *"globex only"* ]] && ok "this tenant does not see the other tenant's note" || ko "tenant isolation leak: $r"
  r=$(curl -s --cacert "$W/edge/ca.crt" -w '\n%{http_code}' "$G/m/notes/mf-manifest.json"); expect "GET /m/notes/mf-manifest.json" 200 "$r"
  local entry; entry=$(body <<<"$r" | pyget "d['metaData']['remoteEntry']['name']")
  r=$(curl -s --cacert "$W/edge/ca.crt" -o /dev/null -w 'x\n%{http_code}' "$G/m/notes/$entry"); expect "GET /m/notes/$entry" 200 "$r"
  r=$(req op GET '/gateway/v1/docs/search?q=notes&module=notes')
  local hits; hits=$(body <<<"$r" | pyget "[(i['module'], i['slug']) for i in d['items']]" 2>/dev/null || echo "?")
  [[ $(code <<<"$r") = 200 && $hits == *notes* ]] && ok "docs search finds notes pages: $hits" || ko "docs search: $r"
}

check_events() {
  local a=$W/sse-auditor.txt o=$W/sse-globex.txt
  timeout 10 curl -sN --cacert "$W/edge/ca.crt" -b "$(jar auditor)" -H 'Accept: text/event-stream' "$G/gateway/v1/stream" >"$a" 2>/dev/null &
  local pa=$!
  timeout 10 curl -sN --cacert "$W/edge/ca.crt" -b "$(jar globex)" -H 'Accept: text/event-stream' "$G/gateway/v1/stream" >"$o" 2>/dev/null &
  local po=$!
  sleep 2
  local r id; r=$(req op POST /api/notes/v1/notes '{"title":"event probe"}'); id=$(body <<<"$r" | pyget "d['id']")
  wait "$pa" "$po" || true # only the two streams: the services are children too
  grep -q '^event: notes.created' "$a" && grep -q "$id" "$a" \
    && ok "SSE (same tenant): $(grep -A1 '^event: notes.created' "$a" | tr '\n' ' ' | cut -c1-200)" \
    || ko "SSE: notes.created $id not seen by the tenant ($(tr '\n' ' ' <"$a" | head -c 300))"
  grep -q "$id" "$o" && ko "SSE: other tenant received $id" || ok "SSE: the other tenant's stream did not receive it"
}

check_deregistration() {
  local t1 w=""; t1=$(date -u +%FT%T.%NZ)
  notes_down
  # The gateway's audit writer is asynchronous: poll for the row.
  for _ in $(seq 1 20); do
    w=$(sql gateway "select ts, reason from gateway_audit_events where module='notes' and event_type='registration_withdrawn' and ts >= '$t1'")
    [ -n "$w" ] && break
    sleep 0.5
  done
  [ -n "$w" ] && ok "gateway audit: registration_withdrawn $w" || ko "no registration_withdrawn after shutdown"
  local regs; regs=$(req op GET /gateway/v1/ops/registrations | body | pyget "[i['module'] for i in d['items']]")
  [[ $regs != *notes* ]] && ok "ops/registrations after shutdown: $regs" || ko "notes still registered: $regs"
}

check() {
  [ -e "$W/run/gateway.pid" ] || die "not up; run up first"
  echo "== A. notes with identity.provider: file (SVID minted by lcm bootstrap under the mesh root)"
  T0=$(date -u +%FT%T.%NZ)
  notes_up file "$W/logs/notes-file.log"
  check_registration
  check_api
  check_events
  check_deregistration

  echo "== B. notes with lcm enrolment (token minted through the gateway: auth.v1.Enrollment/MintEnrollmentToken)"
  rm -f "$W/notes-state/svid.json"
  T0=$(date -u +%FT%T.%NZ)
  local r; r=$(req op POST /gateway/v1/ops/enrollment-tokens '{"services":["notes"],"ttl_seconds":600}')
  if [ "$(code <<<"$r")" = 201 ]; then
    (umask 077; body <<<"$r" | pyget "d['token']" | tr -d '\n' >"$W/tokens/notes.token")
    ok "enrolment token minted for $(body <<<"$r" | pyget "d['spiffe_ids']") (not printed)"
  else
    ko "mint enrolment token: $r"
  fi
  notes_up lcm "$W/logs/notes-lcm.log"
  local idl; idl=$(grep -h '"msg":"identity ready"' "$W/logs/notes-lcm.log" | tail -1)
  ok "enrolled over HTTPS: $(cut -c1-230 <<<"$idl")"
  local perm; perm=$(stat -c %a "$W/notes-state/svid.json")
  [ "$perm" = 600 ] && ok "state file written, mode $perm" || ko "state file mode $perm"
  local serial; serial=$(grep -oE '"serial":"[0-9]+"' <<<"$idl")
  check_registration
  check_api
  check_events
  notes_down
  # The token is single-use and spent: a restart must reuse the state file.
  notes_up lcm "$W/logs/notes-lcm-restart.log"
  grep -q "$serial" "$W/logs/notes-lcm-restart.log" && ok "restart reused the persisted SVID ($serial), no token spent" || ko "restart did not reuse the SVID"
  if [ "$LS_RENEWAL" = 1 ]; then
    notes_down
    # Plant a 3-minute SVID (lcm bootstrap, same mesh root) as the state:
    # the provider renews it over mTLS gRPC (lcm.v1.Enrollment/Enroll).
    mkdir -p "$W/short"
    "$BIN/lcmsvc" bootstrap -config "$W/cfg/lcm.yaml" -out "$W/short" -services notes -ttl 3m >>"$W/logs/lcm-bootstrap.log" 2>&1
    python3 -I - "$W" <<'EOF'
import json, os, sys
w = sys.argv[1]
r = lambda p: open(os.path.join(w, p)).read()
st = {"cert_pem": r("short/notes.pem"), "chain_pem": "", "key_pem": r("short/notes.key"), "bundle_pem": r("short/ca.pem")}
p = os.path.join(w, "notes-state/svid.json")
fd = os.open(p + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
os.write(fd, json.dumps(st).encode()); os.close(fd); os.replace(p + ".tmp", p)
EOF
    local exp; exp=$(openssl x509 -in "$W/short/notes.pem" -noout -enddate | cut -d= -f2)
    notes_up lcm "$W/logs/notes-lcm-renew.log"
    log "waiting for the renewal of the SVID expiring $exp (up to 3 min)"
    wait_log "$W/logs/notes-lcm-renew.log" '"msg":"identity renewed"' "gRPC renewal" 200
    ok "renewed: $(grep -h '"msg":"identity renewed"' "$W/logs/notes-lcm-renew.log" | tail -1 | cut -c1-200)"
    grep -q '"caller":"notes".*"operation":"/lcm.v1.Enrollment/Enroll","outcome":"ok"' "$W/logs/lcm.log" \
      && ok "lcm log: /lcm.v1.Enrollment/Enroll from notes ok" || ko "no Enroll call from notes in the lcm log"
    while [ "$(date +%s)" -le "$(date -d "$exp" +%s)" ]; do sleep 5; done
    r=$(req op GET /api/notes/v1/notes); expect "API through the gateway after the old SVID expired" 200 "$r"
  fi
  check_deregistration
  echo
  [ "$FAILS" = 0 ] && echo "ALL CHECKS PASSED" || echo "$FAILS CHECK(S) FAILED"
  [ "$FAILS" = 0 ]
}

down() {
  for s in $LS_EXTRA_SERVICES notes gateway auth lcm openfga valkey; do stop "$s"; done
  if [ -f "$W/pgdata/postmaster.pid" ]; then "$C/pg/bin/pg_ctl" -D "$W/pgdata" -m fast stop >/dev/null && log "stopped postgres"; fi
  log "down (work dir kept: $W; remove it to start from scratch)"
}

clean() {
  down
  case "$W" in */*livestack*) rm -rf "$W" && log "removed $W" ;; *) die "refusing to remove $W (no 'livestack' in the path)" ;; esac
}

# Sourced by another module's runner: define everything, run nothing.
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0

case "${1:-}" in
  up) up ;;
  check) check ;;
  down) down ;;
  clean) clean ;;
  all)
    trap down EXIT
    up
    check
    ;;
  *) echo "usage: $0 up|check|down|all|clean" >&2; exit 2 ;;
esac
