//! The notes module end to end, in process: the fake platform
//! (`tangra_sdk::testutil::platform`: `gateway` and `auth` over mTLS), the
//! module built by `module::build` with an SVID from the platform's CA, and
//! requests made over mTLS as the gateway would make them.
//!
//! The event-bus part needs a Valkey: `TANGRA_TEST_VALKEY_ADDR=host:port`
//! (plaintext, no ACL; CI's service container), else a server binary from
//! `$VALKEY_SERVER`, `valkey-server` or `redis-server` on `PATH` is
//! started; without either the events checks are skipped with a notice.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use serde_json::{Value, json};
use tangra_notes::config::NotesFile;
use tangra_notes::module::{self, Options};
use tangra_notes::{VERSION, docs, manifest};
use tangra_sdk::events::{self, ValkeyConfig};
use tangra_sdk::log::{Capture, Level, Logger};
use tangra_sdk::testutil::MemoryProvider;
use tangra_sdk::testutil::platform::{Platform, TestResponse};

const TD: &str = "example.org";
const ISSUER: &str = "https://portal.example.org:8443";

const POLICY: &str = r#"version: notes-test-1
rules:
  - {id: gateway-forwards, from: ["spiffe://example.org/svc/gateway"], to: ["notes"], operations: ["GET *", "HEAD *", "POST *", "PUT *"], effect: allow}
"#;

struct Valkey {
    addr: String,
    _child: Option<ChildGuard>,
    _dir: Option<tempfile::TempDir>,
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn valkey() -> Option<Valkey> {
    if let Ok(addr) = std::env::var("TANGRA_TEST_VALKEY_ADDR") {
        return Some(Valkey {
            addr,
            _child: None,
            _dir: None,
        });
    }
    let bin = std::env::var("VALKEY_SERVER")
        .map(PathBuf::from)
        .ok()
        .or_else(|| {
            let path = std::env::var_os("PATH")?;
            std::env::split_paths(&path)
                .flat_map(|d| [d.join("valkey-server"), d.join("redis-server")])
                .find(|p| p.is_file())
        })?;
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .ok()?
        .local_addr()
        .ok()?
        .port();
    let dir = tempfile::tempdir().ok()?;
    let child = Command::new(bin)
        .args([
            "--bind",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "--save",
            "",
            "--appendonly",
            "no",
        ])
        .arg("--dir")
        .arg(dir.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let guard = ChildGuard(child);
    for _ in 0..100 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return Some(Valkey {
                addr: format!("127.0.0.1:{port}"),
                _child: Some(guard),
                _dir: Some(dir),
            });
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}

fn config(p: &Platform, dir: &std::path::Path, valkey: Option<&Valkey>) -> NotesFile {
    let policy = dir.join("policy.yaml");
    std::fs::write(&policy, POLICY).unwrap();
    let mut yaml = format!(
        "service_name: notes\ntrust_domain: {TD}\nidentity: {{provider: provided}}\n\
authz: {{source: file, path: {}}}\n\
server: {{grpc_addr: \"127.0.0.1:0\", http_addr: \"127.0.0.1:0\"}}\nadmin: {{addr: \"127.0.0.1:0\"}}\n\
gateway: {{service: gateway, issuer: \"{ISSUER}\"}}\nlimits_notes: {{max_notes_per_tenant: 50}}\n",
        policy.display()
    );
    match valkey {
        Some(v) => yaml.push_str(&format!(
            "events: {{enabled: true}}\nvalkey: {{addresses: [\"{}\"], allow_plaintext: true}}\n",
            v.addr
        )),
        None => yaml.push_str("events: {enabled: false}\n"),
    }
    let mut cfg = NotesFile::from_yaml(yaml.as_bytes()).unwrap();
    cfg.framework.discovery.r#static = p.discovery();
    tangra_notes::config::validate(&cfg).unwrap();
    cfg
}

async fn eventually(mut f: impl FnMut() -> bool) -> bool {
    for _ in 0..400 {
        if f() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    false
}

#[tokio::test]
async fn notes_module_end_to_end() {
    let mut p = Platform::start(TD, ISSUER).await.unwrap();
    let vk = valkey();
    if vk.is_none() {
        eprintln!("no Valkey (set TANGRA_TEST_VALKEY_ADDR or VALKEY_SERVER): event checks skipped");
    }
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(&p, dir.path(), vk.as_ref());
    let log = Capture::new();
    tangra_sdk::gateway::set_build_version(VERSION);
    let notes = module::build(
        cfg,
        Options {
            logger: Some(Logger::new(log.clone(), Level::Debug)),
            identity: Some(MemoryProvider::new(&p.ca, &p.ca.issue("notes").unwrap()).unwrap()),
            registration_every: Some((Duration::from_millis(200), Duration::from_secs(300))),
        },
    )
    .await
    .unwrap();
    let app = notes.app.clone();
    let verifier = std::sync::Arc::clone(&notes.verifier);
    let digest = notes.docs_digest.clone();
    let serves_ui = notes.serves_ui;
    let addr = app.http_local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let done = tokio::spawn(notes.run_until(async {
        let _ = rx.await;
    }));

    // Gateway registration: the manifest, the docs digest, the release.
    assert!(
        eventually(|| p.gateway.counts().0 >= 1).await,
        "registered with the gateway"
    );
    let reg = p.gateway.last().unwrap();
    let m = reg.manifest.clone().unwrap();
    assert_eq!(
        (m.module.as_str(), m.version.as_str()),
        ("notes", manifest::VERSION)
    );
    assert_eq!(m, manifest::manifest().unwrap().to_proto().unwrap());
    assert_eq!(reg.docs_digest, digest);
    assert_eq!(reg.docs_digest, docs::bundle().unwrap().digest());
    assert_eq!(reg.build_version, VERSION);
    assert_eq!(Some(reg.backend.unwrap().http_url), app.http_url());
    assert_eq!(p.gateway.state().peers[0], "spiffe://example.org/svc/notes");

    // Auth registration: permissions, roles, grants.
    assert!(
        eventually(|| !p.auth.registrations().is_empty()).await,
        "registered with auth"
    );
    let (peer, req) = p.auth.registrations().remove(0);
    assert_eq!(peer, "spiffe://example.org/svc/notes");
    assert_eq!(req, manifest::registration().request());

    // The image's healthcheck probes the admin listener's /readyz.
    let admin = app.admin_url().trim_start_matches("http://").to_owned();
    tangra_notes::healthcheck::probe(&admin).await.unwrap();

    // The verifier has auth's keys.
    assert!(
        eventually(|| verifier.keys_fetched_at().is_some()).await,
        "keys fetched"
    );

    let alice = format!("Bearer {}", p.token("u-alice", "t1", &["member"]));
    let bob = format!("Bearer {}", p.token("u-bob", "t1", &["member"]));
    let mod_ = format!("Bearer {}", p.token("u-mod", "t1", &["member"]));
    let carol = format!("Bearer {}", p.token("u-carol", "t2", &["member"]));
    let call = |method: &'static str, path: String, auth: Option<String>, body: &'static str| {
        let p = &p;
        async move {
            let mut h: Vec<(&str, &str)> = vec![("x-csrf-token", "csrf-1"), ("x-request-id", "req-42")];
            if let Some(a) = &auth {
                h.push(("authorization", a.as_str()));
            }
            if !body.is_empty() {
                h.push(("content-type", "application/json"));
            }
            p.call(addr, "notes", method, &path, &h, body).await.unwrap()
        }
    };
    let notes_path = || "/api/notes/v1/notes".to_owned();

    // Public route: no token needed.
    let r = call("GET", "/api/notes/v1/info".into(), None, "").await;
    assert_eq!(r.status, 200);
    assert_eq!(r.json(), json!({"module": "notes", "version": VERSION}));
    assert_eq!(r.headers["x-request-id"], "req-42", "correlation id echoed");

    // No or a bad token: 401 with the challenge.
    let r = call("POST", notes_path(), None, r#"{"title":"x"}"#).await;
    assert_eq!((r.status, r.json()), (401, json!({"reason": "unauthenticated"})));
    assert_eq!(r.headers["www-authenticate"], "Bearer realm=\"freya\"");
    let forged = format!("Bearer {}", p.token("u-alice", "t1", &[]).replace('.', "x"));
    assert_eq!(call("GET", notes_path(), Some(forged), "").await.status, 401);

    // Create (validation, then success) as alice in t1.
    let r = call("POST", notes_path(), Some(alice.clone()), "{").await;
    assert_eq!(r.json(), json!({"reason": "malformed_body"}));
    let r = call("POST", notes_path(), Some(alice.clone()), r#"{"title":"  "}"#).await;
    assert_eq!(r.status, 422);
    assert_eq!(r.json()["detail"]["fields"]["title"], "required");
    let after = match &vk {
        Some(v) => {
            let c = events::Client::connect(&ValkeyConfig {
                addresses: vec![v.addr.clone()],
                allow_plaintext: true,
                ..ValkeyConfig::default()
            })
            .await
            .expect("valkey reachable");
            Some((c, events::key("t1")))
        }
        None => None,
    };
    let last_id = match &after {
        Some((c, k)) => c.xlast(k).await.unwrap(),
        None => String::new(),
    };
    let r = call(
        "POST",
        notes_path(),
        Some(alice.clone()),
        r#"{"title":"Groceries","body":"milk"}"#,
    )
    .await;
    assert_eq!(r.status, 201, "{}", r.body);
    assert_eq!(r.headers["content-type"], "application/json");
    assert_eq!(r.headers["cache-control"], "no-store");
    assert_eq!(r.headers["x-content-type-options"], "nosniff");
    let note = r.json();
    let id = note["id"].as_str().unwrap().to_owned();
    assert_eq!(
        (note["title"].clone(), note["author_id"].clone()),
        (json!("Groceries"), json!("u-alice"))
    );
    call("POST", notes_path(), Some(bob.clone()), r#"{"title":"Agenda"}"#).await;

    // The event on the tenant's stream: who and which note, never content.
    if let Some((c, k)) = &after {
        let es = c
            .xread(
                k,
                if last_id.is_empty() { "0" } else { &last_id },
                Duration::from_secs(2),
                10,
            )
            .await
            .unwrap();
        let e = es
            .iter()
            .find(|e| e.fields["type"] == "notes.created")
            .expect("notes.created published");
        assert_eq!(e.fields["to"], "*");
        let data: Value = serde_json::from_str(&e.fields["data"]).unwrap();
        assert_eq!(data, json!({"id": id, "author_id": "u-alice"}));
    }

    // List: tenant-scoped, sorted, validated.
    let r = call(
        "GET",
        format!("{}?sort=title&order=asc", notes_path()),
        Some(bob.clone()),
        "",
    )
    .await;
    assert_eq!(r.status, 200);
    let page = r.json();
    assert_eq!(page["total"], 2);
    assert_eq!(page["items"][0]["title"], "Agenda");
    assert_eq!(
        (
            page["sort"].clone(),
            page["order"].clone(),
            page["page_size"].clone()
        ),
        (json!("title"), json!("asc"), json!(25))
    );
    let r = call("GET", format!("{}?q=groc", notes_path()), Some(alice.clone()), "").await;
    assert_eq!(r.json()["total"], 1);
    let r = call("GET", notes_path(), Some(carol.clone()), "").await;
    assert_eq!(
        (r.status, r.json()["total"].clone()),
        (200, json!(0)),
        "another tenant sees nothing"
    );
    for (q, param) in [
        ("sort=author_id", "sort"),
        ("page_size=500", "page_size"),
        ("cursor=x", "cursor"),
    ] {
        let r: TestResponse = call("GET", format!("{}?{q}", notes_path()), Some(alice.clone()), "").await;
        assert_eq!(r.status, 422, "{q}");
        assert_eq!(
            r.json(),
            json!({"reason": "validation_failed", "detail": {"param": param}})
        );
    }

    // Read: another tenant's note does not exist for carol.
    assert_eq!(
        call("GET", format!("{}/{id}", notes_path()), Some(bob.clone()), "")
            .await
            .status,
        200
    );
    let r = call("GET", format!("{}/{id}", notes_path()), Some(carol.clone()), "").await;
    assert_eq!((r.status, r.json()), (404, json!({"reason": "not_found"})));

    // Remove: bob is not the author and auth does not grant him notes:admin.
    p.auth.grant("u-bob", &["notes:read", "notes:write"]);
    p.auth
        .grant("u-mod", &["notes:read", "notes:write", "notes:admin"]);
    let remove = format!("{}/{id}/remove", notes_path());
    let r = call("POST", remove.clone(), Some(bob.clone()), "").await;
    assert_eq!((r.status, r.json()), (403, json!({"reason": "forbidden"})));
    let check = p.auth.state().checks.last().cloned().unwrap();
    assert_eq!(
        (
            check.tenant_id.as_str(),
            check.user_id.as_str(),
            check.resource.as_str(),
            check.action.as_str(),
            check.module.as_str()
        ),
        ("t1", "u-bob", "notes", "admin", "notes")
    );
    assert_eq!(
        call("POST", remove.clone(), Some(carol.clone()), "").await.status,
        404
    );
    let r = call("POST", remove.clone(), Some(mod_.clone()), "").await;
    assert_eq!(r.status, 204, "a moderator removes any note");
    assert_eq!(
        call("GET", format!("{}/{id}", notes_path()), Some(alice.clone()), "")
            .await
            .status,
        404
    );

    // Unknown paths and methods.
    let r = call("GET", "/api/notes/v1/unknown".into(), Some(alice.clone()), "").await;
    assert_eq!((r.status, r.body.as_str()), (404, "{\"reason\":\"not_found\"}\n"));
    let r = call("PUT", notes_path(), Some(alice.clone()), "").await;
    assert_eq!(
        (r.status, r.json()),
        (405, json!({"reason": "method_not_allowed"}))
    );

    // The help bundle: the gateway only (a peer the policy refuses never
    // reaches the handler).
    let r = p
        .call(addr, "notes", "GET", "/docs/v1/bundle", &[], "")
        .await
        .unwrap();
    assert_eq!(r.status, 200);
    assert_eq!(r.headers["etag"], format!("\"{digest}\"").as_str());
    let r = p
        .call_as("lcm", addr, "notes", "GET", "/docs/v1/bundle", &[], "")
        .await
        .unwrap();
    assert_eq!((r.status, r.body.as_str()), (403, "{\"reason\":\"denied\"}\n"));

    // The UI remote, when this build embeds one.
    let r = p
        .call(addr, "notes", "GET", "/ui/mf-manifest.json", &[], "")
        .await
        .unwrap();
    if serves_ui {
        assert_eq!(r.status, 200);
        assert_eq!(r.headers["cache-control"], "no-cache");
        assert!(
            r.json()["name"] == "notes" || r.json()["id"] == "notes",
            "{}",
            r.body
        );
    } else {
        assert_eq!(r.status, 404);
        eprintln!("this build serves no UI remote (feature `ui` and a built ui/dist): UI check skipped");
    }

    // Shutdown withdraws the lease.
    let _ = tx.send(());
    tokio::time::timeout(Duration::from_secs(20), done)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(p.gateway.counts().2, 1, "deregistered on shutdown");
    assert!(log.contents().contains("\"msg\":\"gateway lease\""));
    tangra_sdk::gateway::set_build_version("");
    p.stop().await;
}
