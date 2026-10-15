//! JWKS (authclient `jwks.go`, `http.go`): Ed25519 keys (RFC 8037) and the
//! `/.well-known/jwks.json` key source over HTTPS.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use super::token::decode_raw_url;
use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde::{Deserialize, Serialize};

use super::verifier::{AuthError, KeySource, PublicKey};

/// The largest accepted key set (jwks.go:47).
pub const MAX_JWKS_BYTES: usize = 64 << 10;

/// An Ed25519 verification key with the service's key state.
#[allow(missing_docs)]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwk {
    #[serde(default)]
    pub kty: String,
    #[serde(default)]
    pub crv: String,
    #[serde(default)]
    pub kid: String,
    #[serde(default)]
    pub x: String,
    #[serde(default, rename = "use")]
    pub use_: String,
    #[serde(default)]
    pub alg: String,
    /// `active`, `retiring` or `retired`.
    #[serde(default, rename = "freya_state", skip_serializing_if = "String::is_empty")]
    pub state: String,
}

/// The published key set.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwks {
    /// The keys.
    #[serde(default)]
    pub keys: Vec<Jwk>,
}

impl Jwk {
    /// Renders an Ed25519 public key (authclient `NewJWK`).
    pub fn new(kid: &str, public_key: &[u8], state: &str) -> Self {
        Self {
            kty: "OKP".into(),
            crv: "Ed25519".into(),
            kid: kid.into(),
            x: URL_SAFE_NO_PAD.encode(public_key),
            use_: "sig".into(),
            alg: "EdDSA".into(),
            state: state.into(),
        }
    }

    /// Decodes the key, refusing anything that is not Ed25519/EdDSA.
    pub fn public_key(&self) -> Result<PublicKey, AuthError> {
        if self.kty != "OKP"
            || self.crv != "Ed25519"
            || (!self.alg.is_empty() && self.alg != "EdDSA")
            || self.kid.is_empty()
        {
            return Err(AuthError(format!("authclient: unsupported key {:?}", self.kid)));
        }
        match decode_raw_url(&self.x) {
            Some(raw) if raw.len() == 32 => Ok(raw),
            _ => Err(AuthError(format!("authclient: malformed key {:?}", self.kid))),
        }
    }
}

/// Decodes a key set into kid → key; one bad key fails the whole set so a
/// poisoned document is never partially trusted (authclient `ParseJWKS`).
pub fn parse_jwks(data: &[u8]) -> Result<HashMap<String, PublicKey>, AuthError> {
    if data.len() > MAX_JWKS_BYTES {
        return Err(AuthError("authclient: jwks too large".into()));
    }
    let set: Jwks = serde_json::from_slice(data).map_err(|e| AuthError(format!("authclient: jwks: {e}")))?;
    let mut out = HashMap::with_capacity(set.keys.len());
    for k in &set.keys {
        let pk = k.public_key()?;
        if out.contains_key(&k.kid) {
            return Err(AuthError(format!("authclient: duplicate kid {:?}", k.kid)));
        }
        out.insert(k.kid.clone(), pk);
    }
    Ok(out)
}

/// Fetches `/.well-known/jwks.json` over HTTPS (authclient `HTTPKeys`):
/// `GET` with `Accept: application/json`, 10s timeout, status 200, at most
/// 64 KiB. Redirects are not followed (Go's client follows up to 10).
#[derive(Clone)]
pub struct HttpKeys {
    /// The `https://` URL.
    pub url: String,
    /// TLS client config (default: system roots, ALPN h2/http1.1).
    pub tls: Option<Arc<rustls::ClientConfig>>,
}

impl std::fmt::Debug for HttpKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpKeys")
            .field("url", &self.url)
            .finish_non_exhaustive()
    }
}

fn system_tls() -> Result<Arc<rustls::ClientConfig>, AuthError> {
    let mut roots = rustls::RootCertStore::empty();
    for c in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(c);
    }
    let mut cfg =
        rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| AuthError(e.to_string()))?
            .with_root_certificates(roots)
            .with_no_client_auth();
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

impl HttpKeys {
    async fn fetch(&self) -> Result<Vec<u8>, AuthError> {
        let e = |x: &dyn std::fmt::Display| AuthError(format!("authclient: jwks: {x}"));
        let uri: http::Uri = self.url.parse().map_err(|x| e(&x))?;
        let host = uri.host().ok_or_else(|| e(&"missing host"))?.to_owned();
        let port = uri.port_u16().unwrap_or(443);
        let tls = match &self.tls {
            Some(t) => Arc::clone(t),
            None => system_tls()?,
        };
        let name = rustls_pki_types::ServerName::try_from(host.trim_matches(['[', ']']).to_owned())
            .map_err(|x| e(&x))?;
        let tcp = tokio::net::TcpStream::connect((host.trim_matches(['[', ']']), port))
            .await
            .map_err(|x| e(&x))?;
        let stream = tokio_rustls::TlsConnector::from(tls)
            .connect(name, tcp)
            .await
            .map_err(|x| e(&x))?;
        let h2 = stream.get_ref().1.alpn_protocol() == Some(b"h2");
        let req = http::Request::get(uri.clone())
            .header(http::header::ACCEPT, "application/json")
            .header(
                http::header::HOST,
                uri.authority().map(ToString::to_string).unwrap_or_default(),
            )
            .body(Empty::<Bytes>::new())
            .map_err(|x| e(&x))?;
        let io = TokioIo::new(stream);
        let resp = if h2 {
            let (mut send, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
                .await
                .map_err(|x| e(&x))?;
            tokio::spawn(conn);
            send.send_request(req).await.map_err(|x| e(&x))?
        } else {
            let (mut send, conn) = hyper::client::conn::http1::handshake(io)
                .await
                .map_err(|x| e(&x))?;
            tokio::spawn(conn);
            send.send_request(req).await.map_err(|x| e(&x))?
        };
        if resp.status() != http::StatusCode::OK {
            return Err(AuthError(format!(
                "authclient: jwks: status {}",
                resp.status().as_u16()
            )));
        }
        // io.LimitReader(body, 64 KiB + 1): one byte over trips ParseJWKS.
        let mut body = Vec::new();
        let mut b = resp.into_body();
        while let Some(frame) = b.frame().await {
            let frame = frame.map_err(|x| e(&x))?;
            if let Some(d) = frame.data_ref() {
                body.extend_from_slice(d);
                if body.len() > MAX_JWKS_BYTES {
                    body.truncate(MAX_JWKS_BYTES + 1);
                    break;
                }
            }
        }
        Ok(body)
    }
}

#[async_trait::async_trait]
impl KeySource for HttpKeys {
    async fn keys(&self) -> Result<HashMap<String, PublicKey>, AuthError> {
        if !self.url.starts_with("https://") {
            return Err(AuthError("authclient: jwks url must be https".into()));
        }
        let body = tokio::time::timeout(Duration::from_secs(10), self.fetch())
            .await
            .map_err(|_| AuthError("authclient: jwks: timeout".into()))??;
        parse_jwks(&body)
    }
}
