//! The event bus against a real Valkey (or Redis) server: TLS 1.3 with an
//! ACL user, plaintext, the exact XADD field layout, and the consumer loop.
//!
//! The server binary comes from `$VALKEY_SERVER`, else `valkey-server` or
//! `redis-server` on `PATH`; without one the tests print a notice and pass.
#![cfg(feature = "events")]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tangra_sdk::events::{self, Client, ConsumeOptions, Entry, Publisher, Target, ValkeyConfig};
use tokio_util::sync::CancellationToken;

fn server_binary() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("VALKEY_SERVER") {
        return Some(PathBuf::from(p));
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .flat_map(|d| [d.join("valkey-server"), d.join("redis-server")])
        .find(|p| p.is_file())
}

struct Server {
    child: Child,
    port: u16,
    _dir: tempfile::TempDir,
    ca: PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

const PASSWORD: &str = "s3cret-password-for-tests";

/// Starts a server with ACL user `deployer`; TLS (server cert for
/// localhost from a fresh CA) unless `plain`.
fn start(bin: &Path, plain: bool) -> Server {
    let dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "test valkey ca");
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let issuer = rcgen::Issuer::new(ca_params, ca_key);
    let srv_key = rcgen::KeyPair::generate().unwrap();
    let srv_params = rcgen::CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
    let srv_cert = srv_params.signed_by(&srv_key, &issuer).unwrap();
    let ca = dir.path().join("ca.pem");
    std::fs::write(&ca, ca_cert.pem()).unwrap();
    std::fs::write(dir.path().join("srv.pem"), srv_cert.pem()).unwrap();
    std::fs::write(dir.path().join("srv.key"), srv_key.serialize_pem()).unwrap();
    let net = if plain {
        format!("port {port}\n")
    } else {
        format!(
            "port 0\ntls-port {port}\ntls-cert-file {d}/srv.pem\ntls-key-file {d}/srv.key\n\
             tls-ca-cert-file {d}/ca.pem\ntls-auth-clients no\n",
            d = dir.path().display()
        )
    };
    let conf = format!(
        "bind 127.0.0.1\n{net}save \"\"\nappendonly no\ndir {}\n\
         user default off\nuser deployer on >{PASSWORD} ~* &* +@all\n",
        dir.path().display()
    );
    std::fs::write(dir.path().join("valkey.conf"), conf).unwrap();
    let child = Command::new(bin)
        .arg(dir.path().join("valkey.conf"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    for _ in 0..100 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Server {
        child,
        port,
        _dir: dir,
        ca,
    }
}

fn config(s: &Server, plain: bool) -> ValkeyConfig {
    ValkeyConfig {
        addresses: vec![format!("localhost:{}", s.port)],
        username: "deployer".into(),
        password: PASSWORD.into(),
        allow_plaintext: plain,
        ca_file: if plain {
            String::new()
        } else {
            s.ca.display().to_string()
        },
    }
}

fn now_ms() -> i64 {
    i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()).unwrap()
}

macro_rules! need_server {
    () => {
        match server_binary() {
            Some(b) => b,
            None => {
                eprintln!("no valkey-server/redis-server (set VALKEY_SERVER): integration skipped");
                return;
            }
        }
    };
}

#[tokio::test]
async fn publishes_over_tls_with_the_deployer_field_layout() {
    let bin = need_server!();
    let s = start(&bin, false);
    let client = Client::connect(&config(&s, false)).await.expect("connect");
    client.ping().await.expect("ping");
    let before = now_ms();
    let id = Publisher::new(client.clone())
        .publish(
            "tenant-1",
            &Target::Users(vec!["u1".into(), "u2".into()]),
            "job.finished",
            &serde_json::json!({"job_id": "j1", "note": "<b>&"}),
        )
        .await
        .expect("publish");
    let got = client
        .xread(&events::key("tenant-1"), "0-0", Duration::from_millis(10), 10)
        .await
        .expect("xread");
    assert_eq!(got.len(), 1);
    let e = &got[0];
    assert_eq!(e.id, id);
    assert_eq!(
        e.fields.keys().map(String::as_str).collect::<Vec<_>>(),
        ["at", "data", "to", "type"]
    );
    assert_eq!(e.fields["to"], "u1,u2");
    assert_eq!(e.fields["type"], "job.finished");
    // Go's json.Marshal: sorted keys, HTML-safe escapes.
    assert_eq!(
        e.fields["data"],
        "{\"job_id\":\"j1\",\"note\":\"\\u003cb\\u003e\\u0026\"}"
    );
    let at: i64 = e.fields["at"].parse().unwrap();
    assert!(at >= before && at <= now_ms());
    assert_eq!(client.xlast(&events::key("tenant-1")).await.unwrap(), id);
    assert_eq!(client.xlast(&events::key("empty")).await.unwrap(), "");

    // Refusals happen before anything is sent.
    let p = Publisher::new(client.clone());
    let err = p
        .publish_raw("tenant-1", &Target::All, "revoked", b"{}")
        .await
        .unwrap_err();
    assert_eq!(err.to_string(), "stream: reserved event type");
    assert_eq!(
        client
            .xread(&events::key("tenant-1"), &id, Duration::from_millis(10), 10)
            .await
            .unwrap()
            .len(),
        0
    );
    // Empty raw data is "{}".
    let id2 = p
        .publish_raw("tenant-1", &Target::All, "ping", b"")
        .await
        .unwrap();
    let got = client
        .xread(&events::key("tenant-1"), &id, Duration::from_millis(10), 10)
        .await
        .unwrap();
    assert_eq!(
        (
            got[0].id.as_str(),
            got[0].fields["data"].as_str(),
            got[0].fields["to"].as_str()
        ),
        (id2.as_str(), "{}", "*")
    );
}

#[tokio::test]
async fn tls_and_acl_are_enforced() {
    let bin = need_server!();
    let s = start(&bin, false);
    let mut bad = config(&s, false);
    bad.password = "wrong-password".into();
    assert!(Client::connect(&bad).await.is_err(), "wrong password accepted");
    // Plaintext against the TLS port.
    let plain = config(&s, true);
    assert!(
        Client::connect(&plain).await.is_err(),
        "plaintext accepted on TLS"
    );
    // A server certificate from another CA (system roots, no ca_file).
    let mut other = config(&s, false);
    other.ca_file = String::new();
    assert!(Client::connect(&other).await.is_err(), "unknown CA accepted");
    // The production rule.
    assert!(plain.validate(true).is_err());
}

#[tokio::test]
async fn plaintext_when_allowed() {
    let bin = need_server!();
    let s = start(&bin, true);
    let client = Client::connect(&config(&s, true)).await.expect("connect");
    let id = Publisher::new(client.clone())
        .publish_raw("t", &Target::All, "hello", br#"{"a":1}"#)
        .await
        .unwrap();
    assert!(id.contains('-'));
}

#[tokio::test]
async fn consumer_starts_after_the_tail_and_filters() {
    let bin = need_server!();
    let s = start(&bin, false);
    let client = Client::connect(&config(&s, false)).await.unwrap();
    let p = Publisher::new(client.clone()).allow_reserved();
    p.publish_raw(
        "t1",
        &Target::All,
        "certificate.issued",
        br#"{"certificate_id":"old"}"#,
    )
    .await
    .unwrap();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<(String, Entry)>();
    let stop = CancellationToken::new();
    let opts = ConsumeOptions {
        own_module: "deployer".into(),
        types: vec!["certificate.issued".into(), "certificate.revoked".into()],
        block: Duration::from_millis(200),
        ..ConsumeOptions::default()
    };
    let c2 = client.clone();
    let st = stop.clone();
    let task = tokio::spawn(async move {
        let tenants = vec!["t1".to_owned(), "t2".to_owned()];
        events::consume(&c2, &tenants, opts, st, |t, e| {
            let tx = tx.clone();
            async move {
                let _ = tx.send((t, e));
            }
        })
        .await;
    });
    tokio::time::sleep(Duration::from_millis(500)).await;
    p.publish_raw(
        "t1",
        &Target::All,
        "certificate.renewed",
        br#"{"certificate_id":"r"}"#,
    )
    .await
    .unwrap();
    // The module's own event (loop guard): a `module` field equal to ours.
    client
        .xadd(
            &events::key("t1"),
            &[
                ("module".into(), "deployer".into()),
                ("type".into(), "certificate.issued".into()),
                ("data".into(), "{}".into()),
            ],
            events::DEFAULT_MAX_LEN,
        )
        .await
        .unwrap();
    let want1 = p
        .publish_raw(
            "t1",
            &Target::All,
            "certificate.issued",
            br#"{"certificate_id":"c1"}"#,
        )
        .await
        .unwrap();
    let want2 = p
        .publish_raw(
            "t2",
            &Target::Users(vec!["u".into()]),
            "certificate.revoked",
            br#"{"certificate_id":"c2"}"#,
        )
        .await
        .unwrap();
    let mut got = Vec::new();
    while got.len() < 2 {
        let (t, e) = tokio::time::timeout(Duration::from_secs(10), rx.recv())
            .await
            .expect("event in time")
            .expect("open");
        got.push((t, e.id, e.fields["data"].clone()));
    }
    got.sort();
    assert_eq!(
        got,
        vec![
            ("t1".to_owned(), want1, r#"{"certificate_id":"c1"}"#.to_owned()),
            ("t2".to_owned(), want2, r#"{"certificate_id":"c2"}"#.to_owned()),
        ]
    );
    // Nothing else (the old, renewed and own events were skipped).
    assert!(
        tokio::time::timeout(Duration::from_millis(600), rx.recv())
            .await
            .is_err()
    );
    stop.cancel();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
}
