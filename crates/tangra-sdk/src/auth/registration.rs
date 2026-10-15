//! Permission, role and grant registration with auth (authclient
//! `registration.go` at `sdk/v4.3.0`, feature 019) and the deployer's
//! registration loop (deployer `internal/app/permissions.go`).

use std::collections::{BTreeMap, HashSet};
use std::sync::OnceLock;
use std::time::Duration;

use regex::Regex;
use tangra_proto::auth::v1 as pb;
use tangra_proto::auth::v1::authorization_client::AuthorizationClient;
use tokio_util::sync::CancellationToken;

use super::verifier::AuthError;
use crate::app::ServiceConn;
use crate::log::{Logger, attr};

/// Most permissions per registration.
pub const MAX_PERMISSIONS: usize = 200;
/// Most module roles.
pub const MAX_ROLES: usize = 20;
/// Most permissions per role.
pub const MAX_ROLE_PERMISSIONS: usize = 200;

/// Built-in roles that may receive grants.
pub const BUILTIN_ROLES: [&str; 5] = ["owner", "admin", "member", "auditor", "operator"];

/// Retry cadence until auth accepts (deployer `registerRetry`).
pub const REGISTER_RETRY: Duration = Duration::from_secs(5);
/// Refresh cadence afterwards (deployer `registerPeriod`).
pub const REGISTER_PERIOD: Duration = Duration::from_secs(5 * 60);
/// Deadline of one registration call (deployer `register`).
pub const REGISTER_TIMEOUT: Duration = Duration::from_secs(15);

fn re(cell: &'static OnceLock<Regex>, p: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(p).unwrap_or_else(|_| unreachable!()))
}

fn module_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    re(&R, r"^[a-z][a-z0-9-]{0,31}$")
}

fn resource_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    re(&R, r"^[a-z][a-z0-9_-]{0,63}$")
}

fn action_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    re(&R, r"^[a-z][a-z0-9_-]{0,31}$")
}

fn role_slug_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    re(&R, r"^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$")
}

fn tenant_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    re(
        &R,
        r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    )
}

/// One permission a module enforces.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Permission {
    /// Resource.
    pub resource: String,
    /// Action.
    pub action: String,
    /// Description.
    pub description: String,
}

/// A ready-made role the module provides in every tenant; `permissions`
/// are `resource:action` references of the same registration (or
/// `<module>:resource:action`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ModuleRole {
    /// `^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$`.
    pub slug: String,
    /// Display name (1-120 characters after trimming).
    pub display_name: String,
    /// Description (≤ 256 bytes).
    pub description: String,
    /// 1-200 permission references.
    pub permissions: Vec<String>,
}

/// What a module registers with auth (`auth.v1.Authorization/RegisterPermissions`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Registration {
    /// The module's service name.
    pub module: String,
    /// Display name (≤ 120 bytes, no control characters).
    pub display_name: String,
    /// The permissions.
    pub permissions: Vec<Permission>,
    /// The complete role set: roles no longer listed are retired in auth.
    pub roles: Vec<ModuleRole>,
    /// Built-in role slug → permission references.
    pub builtin_grants: BTreeMap<String, Vec<String>>,
    /// `builtin_grants` is the complete set: grants no longer listed are
    /// revoked in every tenant (false: grants are only added).
    pub declares_grants: bool,
    /// Limits the registration (empty: every active tenant).
    pub tenant_ids: Vec<String>,
}

/// A registration auth would refuse (authclient `ErrInvalidRegistration`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("authclient: invalid registration: {0}")]
pub struct InvalidRegistration(pub String);

fn invalid(s: impl Into<String>) -> InvalidRegistration {
    InvalidRegistration(s.into())
}

/// ≤ `max` bytes and no control characters.
fn printable(s: &str, max: usize) -> bool {
    s.len() <= max && !s.chars().any(char::is_control)
}

impl Registration {
    /// `resource:action` for a short or own-module qualified reference.
    fn short<'a>(&self, r: &'a str) -> std::borrow::Cow<'a, str> {
        let parts: Vec<&str> = r.split(':').collect();
        if parts.len() == 3 && parts[0] == self.module {
            return format!("{}:{}", parts[1], parts[2]).into();
        }
        r.into()
    }

    /// Checks limits, grammars and that roles and grants only name
    /// permissions of this registration (auth enforces the same rules).
    pub fn validate(&self) -> Result<(), InvalidRegistration> {
        if !module_re().is_match(&self.module) {
            return Err(invalid(format!("module {:?}", self.module)));
        }
        if !printable(&self.display_name, 120) {
            return Err(invalid("display name"));
        }
        if self.permissions.len() > MAX_PERMISSIONS {
            return Err(invalid(format!(
                "{} permissions (max {MAX_PERMISSIONS})",
                self.permissions.len()
            )));
        }
        let mut own = HashSet::new();
        for p in &self.permissions {
            let r = format!("{}:{}", p.resource, p.action);
            if !resource_re().is_match(&p.resource)
                || !action_re().is_match(&p.action)
                || !printable(&p.description, 256)
            {
                return Err(invalid(format!("permission {r:?}")));
            }
            if !own.insert(r.clone()) {
                return Err(invalid(format!("duplicate permission {r:?}")));
            }
        }
        if self.roles.len() > MAX_ROLES {
            return Err(invalid(format!("{} roles (max {MAX_ROLES})", self.roles.len())));
        }
        let mut slugs = HashSet::new();
        for role in &self.roles {
            let name = role.display_name.trim();
            if !role_slug_re().is_match(&role.slug) {
                return Err(invalid(format!("role slug {:?}", role.slug)));
            }
            if slugs.contains(&role.slug) {
                return Err(invalid(format!("duplicate role {:?}", role.slug)));
            }
            if name.is_empty() || !printable(name, 120) || !printable(&role.description, 256) {
                return Err(invalid(format!(
                    "role {:?}: display name or description",
                    role.slug
                )));
            }
            if role.permissions.is_empty() || role.permissions.len() > MAX_ROLE_PERMISSIONS {
                return Err(invalid(format!(
                    "role {:?}: {} permissions (1–{MAX_ROLE_PERMISSIONS})",
                    role.slug,
                    role.permissions.len()
                )));
            }
            slugs.insert(role.slug.clone());
            for p in &role.permissions {
                if !own.contains(self.short(p).as_ref()) {
                    return Err(invalid(format!(
                        "role {:?} names {p:?}, not a permission of this registration",
                        role.slug
                    )));
                }
            }
        }
        for (role, refs) in &self.builtin_grants {
            if !BUILTIN_ROLES.contains(&role.as_str()) {
                return Err(invalid(format!("built-in grant to {role:?}")));
            }
            for p in refs {
                if !own.contains(p) {
                    return Err(invalid(format!(
                        "built-in grant {role:?} → {p:?}, not a permission of this registration"
                    )));
                }
            }
        }
        for t in &self.tenant_ids {
            if !tenant_re().is_match(t) {
                return Err(invalid(format!("tenant id {t:?}")));
            }
        }
        Ok(())
    }

    /// The request (`declares_roles` always: the role set is complete;
    /// grants sorted by role).
    pub fn request(&self) -> pb::RegisterPermissionsRequest {
        pb::RegisterPermissionsRequest {
            permissions: self
                .permissions
                .iter()
                .map(|p| pb::PermissionDef {
                    resource: p.resource.clone(),
                    action: p.action.clone(),
                    description: p.description.clone(),
                })
                .collect(),
            tenant_ids: self.tenant_ids.clone(),
            builtin_grants: self
                .builtin_grants
                .iter()
                .map(|(role, perms)| pb::BuiltinGrant {
                    role: role.clone(),
                    permissions: perms.clone(),
                })
                .collect(),
            module: self.module.clone(),
            module_display_name: self.display_name.clone(),
            roles: self
                .roles
                .iter()
                .map(|r| pb::ModuleRoleDef {
                    slug: r.slug.clone(),
                    display_name: r.display_name.trim().to_owned(),
                    description: r.description.clone(),
                    permissions: r.permissions.iter().map(|p| self.short(p).into_owned()).collect(),
                })
                .collect(),
            declares_roles: true,
            declares_builtin_grants: self.declares_grants,
        }
    }

    /// Validates, sends the registration and logs every skipped built-in
    /// grant (warn) and rejected role (error) (authclient `Register`).
    pub async fn register(
        &self,
        conn: &ServiceConn,
        log: Option<&Logger>,
    ) -> Result<pb::RegisterPermissionsResponse, AuthError> {
        self.validate().map_err(|e| AuthError(e.to_string()))?;
        let ch = conn
            .get()
            .map_err(|e| AuthError(format!("authclient: register permissions: {}", e.0)))?;
        let resp = AuthorizationClient::new(ch)
            .register_permissions(self.request())
            .await
            .map_err(|s| {
                AuthError(format!(
                    "authclient: register permissions: rpc error: code = {:?} desc = {}",
                    s.code(),
                    s.message()
                ))
            })?
            .into_inner();
        if let Some(log) = log {
            let m = self.module.as_str();
            for s in &resp.skipped_grants {
                log.warn(
                    "auth registration: built-in grant skipped",
                    vec![
                        attr("module", m),
                        attr("role", s.role.as_str()),
                        attr("tenants", u64::from(s.tenants)),
                        attr("sample", format!("{:?}", s.sample_tenant_ids)),
                        attr("reason", s.reason.as_str()),
                    ],
                );
            }
            for e in &resp.role_errors {
                log.error(
                    "auth registration: module role rejected",
                    vec![
                        attr("module", m),
                        attr("slug", e.slug.as_str()),
                        attr("reason", e.reason.as_str()),
                    ],
                );
            }
            if !resp.roles_retired.is_empty() {
                log.info(
                    "auth registration: module roles retired",
                    vec![
                        attr("module", m),
                        attr("roles", format!("{:?}", resp.roles_retired)),
                    ],
                );
            }
            if resp.grants_revoked > 0 {
                log.info(
                    "auth registration: built-in grants revoked",
                    vec![attr("module", m), attr("grants", u64::from(resp.grants_revoked))],
                );
            }
        }
        Ok(resp)
    }
}

/// Registers at start, retrying every `retry` until it succeeds, then
/// re-registers every `period` until `stop` (deployer `registrationLoop`;
/// each attempt has a 15s deadline).
pub async fn registration_loop(
    reg: &Registration,
    conn: &ServiceConn,
    log: &Logger,
    retry: Duration,
    period: Duration,
    stop: &CancellationToken,
) {
    let seed = || async {
        match tokio::time::timeout(REGISTER_TIMEOUT, reg.register(conn, Some(log))).await {
            Ok(r) => r.map(|_| ()),
            Err(_) => Err(AuthError("context deadline exceeded".into())),
        }
    };
    while !stop.is_cancelled() {
        let res = tokio::select! {
            () = stop.cancelled() => return,
            r = seed() => r,
        };
        match res {
            Ok(()) => break,
            Err(e) => {
                log.warn("auth registration failed; retrying", vec![attr("err", e.0)]);
                tokio::select! {
                    () = stop.cancelled() => return,
                    () = tokio::time::sleep(retry) => {}
                }
            }
        }
    }
    let mut t = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
    t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            () = stop.cancelled() => return,
            _ = t.tick() => {
                let res = tokio::select! {
                    () = stop.cancelled() => return,
                    r = seed() => r,
                };
                if let Err(e) = res {
                    log.warn("auth registration", vec![attr("err", e.0)]);
                }
            }
        }
    }
}
