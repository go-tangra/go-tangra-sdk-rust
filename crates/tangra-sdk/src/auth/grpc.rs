//! Key and revocation sources over the mesh (authclient `grpc.go`):
//! `auth.v1.Keys/List` and `auth.v1.Sessions/RevokedSince`.

use std::collections::HashMap;

use tangra_proto::auth::v1 as pb;
use tangra_proto::auth::v1::keys_client::KeysClient;
use tangra_proto::auth::v1::sessions_client::SessionsClient;

use super::verifier::{AuthError, KeySource, PublicKey, Revocation, RevocationSource};
use crate::app::ServiceConn;

fn status(s: &tonic::Status) -> AuthError {
    AuthError(format!("rpc error: code = {:?} desc = {}", s.code(), s.message()))
}

/// Keys from `auth.v1.Keys/List` (authclient `GRPCKeys`). Every listed
/// key is trusted whatever its `state`/`not_after` (as in Go: the token's
/// own `exp` bounds it); one unsupported or duplicate key fails the set.
#[derive(Debug, Clone)]
pub struct GrpcKeys {
    /// The connection to `auth`.
    pub conn: ServiceConn,
}

#[async_trait::async_trait]
impl KeySource for GrpcKeys {
    async fn keys(&self) -> Result<HashMap<String, PublicKey>, AuthError> {
        let ch = self.conn.get().map_err(|e| AuthError(e.0))?;
        let resp = KeysClient::new(ch)
            .list(pb::ListKeysRequest {})
            .await
            .map_err(|s| status(&s))?
            .into_inner();
        let mut out = HashMap::with_capacity(resp.keys.len());
        for k in resp.keys {
            if k.kty != "OKP" || k.crv != "Ed25519" || k.public_key.len() != 32 || k.kid.is_empty() {
                return Err(AuthError(format!("authclient: unsupported key {:?}", k.kid)));
            }
            if out.contains_key(&k.kid) {
                return Err(AuthError(format!("authclient: duplicate kid {:?}", k.kid)));
            }
            out.insert(k.kid, k.public_key);
        }
        Ok(out)
    }
}

/// Pages `auth.v1.Sessions/RevokedSince` (authclient `GRPCRevocations`).
#[derive(Debug, Clone)]
pub struct GrpcRevocations {
    /// The connection to `auth`.
    pub conn: ServiceConn,
    /// Page size (0 = the server default).
    pub limit: u32,
}

#[async_trait::async_trait]
impl RevocationSource for GrpcRevocations {
    async fn since(&self, cursor: &str) -> Result<(Vec<Revocation>, String), AuthError> {
        let ch = self.conn.get().map_err(|e| AuthError(e.0))?;
        let resp = SessionsClient::new(ch)
            .revoked_since(pb::RevokedSinceRequest {
                cursor: cursor.to_owned(),
                limit: self.limit,
            })
            .await
            .map_err(|s| status(&s))?
            .into_inner();
        let out = resp
            .revocations
            .into_iter()
            .map(|r| Revocation {
                // Timestamp.AsTime (a nil ts is the Unix epoch).
                ts_unix_nanos: r
                    .ts
                    .map_or(0, |t| i128::from(t.seconds) * 1_000_000_000 + i128::from(t.nanos)),
                kind: r.kind,
                subject_id: r.subject_id,
                tenant_id: r.tenant_id,
                reason: r.reason,
            })
            .collect();
        Ok((out, resp.next_cursor))
    }
}
