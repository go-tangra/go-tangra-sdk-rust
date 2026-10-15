//! Remote authorization and membership calls to auth over the mesh
//! (`auth.v1.Authorization/Check|BatchCheck`, `auth.v1.Profiles/ListMembers`).
//!
//! authclient does not wrap these; this is the thin client the deployer
//! builds by hand (`internal/audience`: `ListMembers` paged by cursor,
//! limit 1000, at most 100 000 ids, 5s per call).

use std::time::Duration;

use tangra_proto::auth::v1 as pb;
use tangra_proto::auth::v1::authorization_client::AuthorizationClient;
use tangra_proto::auth::v1::profiles_client::ProfilesClient;

use crate::app::ServiceConn;

/// Deadline of one call (deployer `audience.callTimeout`).
pub const CALL_TIMEOUT: Duration = Duration::from_secs(5);
/// Page size (deployer `audience.load`).
pub const MEMBERS_PAGE: i32 = 1000;
/// Most member ids collected (deployer `audience.maxMembers`).
pub const MAX_MEMBERS: usize = 100_000;

/// Calls to auth's `Authorization` and `Profiles` services.
#[derive(Debug, Clone)]
pub struct AuthzClient {
    conn: ServiceConn,
}

fn unavailable(e: crate::app::ClientError) -> tonic::Status {
    tonic::Status::unavailable(e.0)
}

async fn deadline<T>(f: impl Future<Output = Result<T, tonic::Status>>) -> Result<T, tonic::Status> {
    tokio::time::timeout(CALL_TIMEOUT, f)
        .await
        .unwrap_or_else(|_| Err(tonic::Status::deadline_exceeded("context deadline exceeded")))
}

impl AuthzClient {
    /// A client over `conn` (normally `ServiceConn::app(&app, "auth")`).
    pub fn new(conn: ServiceConn) -> Self {
        Self { conn }
    }

    /// Decides one permission for a user (`module` names the permission's
    /// module; empty = the calling service).
    pub async fn check(&self, req: pb::CheckRequest) -> Result<pb::CheckResponse, tonic::Status> {
        let mut c = AuthorizationClient::new(self.conn.get().map_err(unavailable)?);
        deadline(async move { Ok(c.check(req).await?.into_inner()) }).await
    }

    /// Decides several permissions for a user, in request order.
    pub async fn batch_check(
        &self,
        req: pb::BatchCheckRequest,
    ) -> Result<pb::BatchCheckResponse, tonic::Status> {
        let mut c = AuthorizationClient::new(self.conn.get().map_err(unavailable)?);
        deadline(async move { Ok(c.batch_check(req).await?.into_inner()) }).await
    }

    /// One page of a tenant's active members.
    pub async fn list_members_page(
        &self,
        req: pb::ListMembersRequest,
    ) -> Result<pb::ListMembersResponse, tonic::Status> {
        let mut c = ProfilesClient::new(self.conn.get().map_err(unavailable)?);
        deadline(async move { Ok(c.list_members(req).await?.into_inner()) }).await
    }

    /// Every active member of `tenant_id`, paging by cursor until an empty
    /// cursor or page (or [`MAX_MEMBERS`]).
    pub async fn list_members(&self, tenant_id: &str) -> Result<Vec<String>, tonic::Status> {
        let mut ids = Vec::new();
        let mut cursor = String::new();
        loop {
            let res = self
                .list_members_page(pb::ListMembersRequest {
                    tenant_id: tenant_id.to_owned(),
                    cursor: cursor.clone(),
                    limit: MEMBERS_PAGE,
                    user_ids: Vec::new(),
                })
                .await?;
            let n = res.user_ids.len();
            ids.extend(res.user_ids);
            if res.next_cursor.is_empty() || n == 0 || ids.len() >= MAX_MEMBERS {
                break;
            }
            cursor = res.next_cursor;
        }
        Ok(ids)
    }
}
