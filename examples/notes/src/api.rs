//! The gateway-facing HTTP API (`api/openapi/notes.yaml`), shaped like the
//! deployer's `internal/httpapi`:
//!
//! - the gateway has already enforced the route's permission
//!   (`x-freya-permission`); the module verifies the platform token
//!   ([`UserAuthLayer`] -> [`User`]) and scopes every read and write to the
//!   token's tenant (another tenant's note is `404`, never `403`);
//! - finer rules are the module's own: removing another author's note asks
//!   auth (`Authorization/Check notes:admin`);
//! - refusals use the closed `{"reason"[,"detail"]}` vocabulary; JSON bodies
//!   are bounded (64 KiB), unknown routes are `404 not_found`, and every
//!   response carries the deployer's security headers.
//!
//! The deployer validates each request against its OpenAPI document with
//! kin-openapi. The SDK has no OpenAPI request validator, so this module
//! checks parameters and bodies in the handlers with the same outcomes:
//! a bad list parameter is `422` with `detail.param`, a body that is not
//! JSON `400 malformed_body`, a body that breaks the schema `422
//! validation_failed`, a missing `X-CSRF-Token` `422`.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Path, RawQuery, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{MethodRouter, any, get, post};
use http::{HeaderMap, StatusCode};
use serde_json::{Map, Value, json};
use tangra_proto::auth::v1::CheckRequest;
use tangra_sdk::auth::{AuthzClient, User, UserAuthLayer, Verifier};
use tangra_sdk::error::{self, ApiError};
use tangra_sdk::events::{Publisher, Target};
use tangra_sdk::listquery::{self, Query, Spec};
use tangra_sdk::log::{Logger, attr};

use crate::manifest::MODULE;
use crate::store::{Note, Store, StoreError, list_spec};

/// JSON bodies of ordinary operations (deployer `MaxBodyBytes`).
pub const MAX_BODY_BYTES: usize = 64 << 10;
/// Title length limit (characters).
pub const MAX_TITLE: usize = 200;
/// Body length limit (characters).
pub const MAX_BODY_CHARS: usize = 10_000;
/// `q` length limit.
pub const MAX_QUERY: usize = 100;
/// The event published for each new note.
pub const EVENT_CREATED: &str = "notes.created";

/// What the handlers share.
#[derive(Clone)]
pub struct ApiState {
    /// Notes.
    pub store: Arc<Store>,
    /// The event bus publisher (`events.enabled`).
    pub events: Option<Arc<Publisher>>,
    /// auth's `Authorization` service.
    pub authz: AuthzClient,
    /// The app's logger.
    pub log: Logger,
    /// The list's sort allow-list.
    pub spec: Arc<Spec>,
    /// The release reported by `GET /api/notes/v1/info`.
    pub version: &'static str,
}

impl ApiState {
    /// State over `store` with the module's list spec.
    pub fn new(
        store: Arc<Store>,
        events: Option<Arc<Publisher>>,
        authz: AuthzClient,
        log: Logger,
        version: &'static str,
    ) -> Self {
        Self {
            store,
            events,
            authz,
            log,
            spec: Arc::new(list_spec()),
            version,
        }
    }
}

/// The API router. Mount it on the app's HTTP server next to the help
/// bundle and the UI remote; the catch-all answers `404 not_found`.
pub fn router(state: ApiState, verifier: Arc<Verifier>) -> Router {
    let protected = Router::new()
        .route("/api/notes/v1/notes", methods(get(list).post(create)))
        .route("/api/notes/v1/notes/{id}", methods(get(get_note)))
        .route("/api/notes/v1/notes/{id}/remove", methods(post(remove)))
        .route_layer(UserAuthLayer::new(verifier));
    Router::new()
        .route("/api/notes/v1/info", methods(get(info)))
        .merge(protected)
        // A real route, not a fallback: the app installs its own fallback.
        .route("/", any(not_found))
        .route("/{*rest}", any(not_found))
        .layer(axum::middleware::map_response(secure))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

/// A declared path answers other methods `405 method_not_allowed`
/// (deployer `validate`).
fn methods(m: MethodRouter<ApiState>) -> MethodRouter<ApiState> {
    m.fallback(|| async { ApiError::new(StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed") })
}

async fn not_found() -> ApiError {
    ApiError::not_found()
}

/// The headers every API response shares (deployer `secure`).
async fn secure(mut r: Response) -> Response {
    error::set_secure_headers(r.headers_mut());
    r
}

/// `GET /api/notes/v1/info` (public).
async fn info(State(s): State<ApiState>) -> Response {
    error::json(StatusCode::OK, &json!({"module": MODULE, "version": s.version}))
}

/// `GET /api/notes/v1/notes`: one page of the caller's tenant's notes.
async fn list(State(s): State<ApiState>, user: User, RawQuery(raw): RawQuery) -> Result<Response, ApiError> {
    let q = Query::parse(raw.as_deref().unwrap_or(""));
    if listquery::legacy(&q) {
        return Err(ApiError::invalid_param(if q.has("cursor") {
            "cursor"
        } else {
            "limit"
        }));
    }
    let req = listquery::parse(&q, &s.spec).map_err(|e| ApiError::invalid_param(e.param))?;
    let filter = q.get("q");
    if filter.chars().count() > MAX_QUERY {
        return Err(ApiError::invalid_param("q"));
    }
    let page = s.store.list(&user.tenant_id, filter, &req);
    Ok(error::json(StatusCode::OK, &page))
}

/// `GET /api/notes/v1/notes/{id}`.
async fn get_note(
    State(s): State<ApiState>,
    user: User,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let note = s
        .store
        .get(&user.tenant_id, &id)
        .ok_or_else(ApiError::not_found)?;
    Ok(error::json(StatusCode::OK, &note))
}

/// `POST /api/notes/v1/notes`: creates a note and announces it on the
/// tenant's event stream.
async fn create(
    State(s): State<ApiState>,
    user: User,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, ApiError> {
    require_csrf(&headers)?;
    let (title, text) = decode_new_note(body).await?;
    let note = s
        .store
        .create(&user.tenant_id, &user.user_id, &title, &text)
        .map_err(|e| match e {
            StoreError::Full => ApiError::conflict(),
        })?;
    publish_created(&s, &user, &note).await;
    Ok(error::json(StatusCode::CREATED, &note))
}

/// `POST /api/notes/v1/notes/{id}/remove`.
async fn remove(
    State(s): State<ApiState>,
    user: User,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    require_csrf(&headers)?;
    let note = s
        .store
        .get(&user.tenant_id, &id)
        .ok_or_else(ApiError::not_found)?;
    if note.author_id != user.user_id && !may_moderate(&s, &user).await? {
        return Err(ApiError::forbidden());
    }
    s.store.remove(&user.tenant_id, &id);
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Whether auth grants the caller `notes:admin` in their tenant. auth
/// unreachable is `503 temporarily_unavailable` (deployer `Fail`).
async fn may_moderate(s: &ApiState, user: &User) -> Result<bool, ApiError> {
    let req = CheckRequest {
        tenant_id: user.tenant_id.clone(),
        user_id: user.user_id.clone(),
        resource: "notes".into(),
        action: "admin".into(),
        module: MODULE.into(),
        ..CheckRequest::default()
    };
    match s.authz.check(req).await {
        Ok(r) => Ok(r.allowed),
        Err(e) => {
            s.log.error(
                "authorization check failed",
                vec![attr("err", e.message()), attr("code", format!("{:?}", e.code()))],
            );
            Err(ApiError::temporarily_unavailable())
        }
    }
}

/// Publishes `notes.created` (id and author only, never the content) to
/// everyone in the tenant. A failed publish is logged; the note stays
/// created (the event is a hint for live views, the list is the truth).
async fn publish_created(s: &ApiState, user: &User, note: &Note) {
    let Some(p) = &s.events else { return };
    let data = json!({"id": note.id, "author_id": note.author_id});
    if let Err(e) = p
        .publish(&user.tenant_id, &Target::All, EVENT_CREATED, &data)
        .await
    {
        s.log.warn(
            "notes: event not sent",
            vec![
                attr("tenant_id", user.tenant_id.as_str()),
                attr("event", EVENT_CREATED),
                attr("err", e.to_string()),
            ],
        );
    }
}

/// The OpenAPI `X-CSRF-Token` header parameter (required, at most 128
/// bytes); a violation is `422 validation_failed` as kin-openapi answers.
fn require_csrf(h: &HeaderMap) -> Result<(), ApiError> {
    match h.get("x-csrf-token") {
        Some(v) if !v.is_empty() && v.len() <= 128 => Ok(()),
        _ => Err(ApiError::validation_failed()),
    }
}

fn field_errors(fields: Map<String, Value>) -> ApiError {
    let mut d = Map::new();
    d.insert("fields".into(), Value::Object(fields));
    ApiError::validation_failed().with_detail(d)
}

/// Reads a `NewNote` (at most [`MAX_BODY_BYTES`]): not JSON is `400
/// malformed_body`, a schema violation `422` with `detail.fields`.
async fn decode_new_note(body: Body) -> Result<(String, String), ApiError> {
    let raw = axum::body::to_bytes(body, MAX_BODY_BYTES)
        .await
        .map_err(|_| ApiError::body_too_large())?;
    let v: Value = serde_json::from_slice(&raw).map_err(|_| ApiError::malformed_body())?;
    let Value::Object(obj) = v else {
        return Err(ApiError::validation_failed());
    };
    let mut errs = Map::new();
    for k in obj.keys() {
        if k != "title" && k != "body" {
            errs.insert(k.clone(), json!("unknown"));
        }
    }
    let title = match obj.get("title") {
        None => {
            errs.insert("title".into(), json!("required"));
            String::new()
        }
        Some(Value::String(t)) => t.trim().to_owned(),
        Some(_) => {
            errs.insert("title".into(), json!("invalid"));
            String::new()
        }
    };
    if !errs.contains_key("title") {
        if title.is_empty() {
            errs.insert("title".into(), json!("required"));
        } else if title.chars().count() > MAX_TITLE {
            errs.insert("title".into(), json!("too_long"));
        } else if title.chars().any(char::is_control) {
            errs.insert("title".into(), json!("invalid"));
        }
    }
    let text = match obj.get("body") {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(b)) if b.chars().count() > MAX_BODY_CHARS => {
            errs.insert("body".into(), json!("too_long"));
            String::new()
        }
        Some(Value::String(b)) => b.clone(),
        Some(_) => {
            errs.insert("body".into(), json!("invalid"));
            String::new()
        }
    };
    if errs.is_empty() {
        Ok((title, text))
    } else {
        Err(field_errors(errs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn decode(s: &str) -> Result<(String, String), ApiError> {
        decode_new_note(Body::from(s.to_owned())).await
    }

    #[tokio::test]
    async fn new_note_validation() {
        assert_eq!(
            decode(r#"{"title":" a ","body":"b"}"#).await.unwrap(),
            ("a".into(), "b".into())
        );
        assert_eq!(decode("{").await.unwrap_err().reason(), "malformed_body");
        assert_eq!(
            decode("[]").await.unwrap_err().status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        let e = decode(r#"{"title":"","x":1}"#).await.unwrap_err();
        assert_eq!(
            e.body(),
            "{\"detail\":{\"fields\":{\"title\":\"required\",\"x\":\"unknown\"}},\"reason\":\"validation_failed\"}\n"
        );
        let long = "t".repeat(MAX_TITLE + 1);
        let e = decode(&format!(r#"{{"title":"{long}"}}"#)).await.unwrap_err();
        assert!(e.body().contains("too_long"));
        let big = "x".repeat(MAX_BODY_BYTES + 1);
        assert_eq!(decode(&big).await.unwrap_err().reason(), "body_too_large");
        assert!(require_csrf(&HeaderMap::new()).is_err());
    }
}
