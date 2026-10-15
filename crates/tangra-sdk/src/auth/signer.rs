//! An Ed25519 token signer for tests (the role of authclient's test
//! `signer`): mints access tokens the [`Verifier`](super::Verifier) accepts.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{Value, json};

use super::verifier::{AuthError, PublicKey};

/// A test signing key.
pub struct TestSigner {
    kid: String,
    key: Ed25519KeyPair,
}

impl std::fmt::Debug for TestSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestSigner")
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

impl TestSigner {
    /// A fresh random key named `kid`.
    pub fn new(kid: &str) -> Result<Self, AuthError> {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).map_err(|e| AuthError(e.to_string()))?;
        Self::from_pkcs8(kid, pkcs8.as_ref())
    }

    /// A deterministic key from a 32-byte seed (fixtures).
    pub fn from_seed(kid: &str, seed: &[u8; 32]) -> Result<Self, AuthError> {
        let key = Ed25519KeyPair::from_seed_unchecked(seed).map_err(|e| AuthError(e.to_string()))?;
        Ok(Self {
            kid: kid.to_owned(),
            key,
        })
    }

    fn from_pkcs8(kid: &str, der: &[u8]) -> Result<Self, AuthError> {
        let key = Ed25519KeyPair::from_pkcs8(der).map_err(|e| AuthError(e.to_string()))?;
        Ok(Self {
            kid: kid.to_owned(),
            key,
        })
    }

    /// The key id.
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// The raw public key.
    pub fn public_key(&self) -> PublicKey {
        self.key.public_key().as_ref().to_vec()
    }

    /// Signs arbitrary header and claims JSON (any `alg`/`kid` the test wants).
    pub fn sign_raw(&self, header: &Value, claims: &Value) -> String {
        let h = URL_SAFE_NO_PAD.encode(header.to_string());
        let c = URL_SAFE_NO_PAD.encode(claims.to_string());
        self.sign_parts(&h, &c)
    }

    /// Signs pre-encoded segments.
    pub fn sign_parts(&self, header_b64: &str, claims_b64: &str) -> String {
        let signing = format!("{header_b64}.{claims_b64}");
        let sig = self.key.sign(signing.as_bytes());
        format!("{signing}.{}", URL_SAFE_NO_PAD.encode(sig.as_ref()))
    }

    /// The standard claims for a user token issued at `iat` (unix seconds)
    /// living `life_secs`: `iss`, `sub`, `tid`, `sid`, `jti`, `iat`, `nbf`,
    /// `exp`, `roles: ["admin"]`, `amr: ["pwd"]`.
    pub fn claims(iss: &str, sub: &str, tid: &str, sid: &str, iat: i64, life_secs: i64) -> Value {
        json!({
            "iss": iss, "sub": sub, "tid": tid, "sid": sid, "jti": format!("j-{iat}-{sub}-{sid}"),
            "iat": iat, "nbf": iat, "exp": iat + life_secs,
            "roles": ["admin"], "amr": ["pwd"],
        })
    }

    /// An EdDSA token with this key's `kid` over `claims`.
    pub fn mint(&self, claims: &Value) -> String {
        self.sign_raw(&json!({"alg": "EdDSA", "typ": "JWT", "kid": self.kid}), claims)
    }
}
