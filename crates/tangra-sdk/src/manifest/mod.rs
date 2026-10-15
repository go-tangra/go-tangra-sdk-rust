//! The gateway manifest a module registers (`gateway.v1.Manifest`).
//!
//! - [`Manifest`] is the typed builder (portal `sdk/pkg/gatewayclient/manifest.go`
//!   at `sdk/v4.2.0`); [`Manifest::to_proto`] is its `Proto()`.
//! - [`validate`] / [`parse`] apply exactly what the gateway applies at
//!   registration (portal `internal/manifest`: `FromProto`, `Parse`,
//!   `Validate`, plus `sdk/api/schema/manifest.schema.json`, vendored in
//!   `schema/`), so a manifest the gateway would refuse fails in the module's
//!   own tests.
//! - [`openapi`] derives the routes from an OpenAPI document carrying the
//!   `x-freya-*` extensions (deployer/warden `pkg/*manifest.Routes`).
//! - [`pin`] ties the manifest content to its version (the gateway refuses a
//!   changed manifest under an unchanged version with `manifest_drift`).
//!
//! ```
//! use tangra_sdk::manifest::{Manifest, Route};
//!
//! let m = Manifest::new("orders", "Orders", "1.0.0")
//!     .prefix("/api/orders")
//!     .permission("orders", "read", "Read orders")
//!     .route(Route::protected("GET", "/api/orders/v1/orders", "orders:read"))
//!     .exposes(["./routes", "./nav"]);
//! m.validate().expect("the gateway accepts it");
//! ```

mod gojson;
pub mod openapi;
pub mod pin;
mod schema;
mod validate;

use std::time::Duration;

use serde_json::{Map, Value};
use tangra_proto::gateway::v1 as pb;

pub use validate::{
    GatewayManifest, GwAbility, GwMethod, GwNav, GwPermission, GwRemote, GwRoute, MAX_CONDITION_BYTES,
    MAX_DURATION_ROUTE, MAX_MANIFEST_BYTES, normalize_prefix, overlaps, parse, validate, validate_conditions,
};

/// A manifest the gateway would refuse (or that cannot be encoded). The
/// message is the gateway's own (`manifest: invalid: ...`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct ManifestError(pub String);

/// The module manifest (gatewayclient `Manifest`). Zero values are omitted
/// on the wire.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Manifest {
    /// Module name (the service name).
    pub module: String,
    /// Display name (1-80 characters).
    pub display_name: String,
    /// `MAJOR.MINOR.PATCH`; bump on every manifest change.
    pub version: String,
    /// Owned path prefixes (e.g. `/api/orders`).
    pub prefixes: Vec<String>,
    /// HTTP routes the gateway proxies.
    pub routes: Vec<Route>,
    /// gRPC methods the gateway proxies.
    pub methods: Vec<Method>,
    /// API permissions the module enforces.
    pub permissions: Vec<Permission>,
    /// CASL abilities bound to the permissions.
    pub abilities: Vec<Ability>,
    /// Module Federation exposes (`./routes`, `./nav`, `./boot`, `./header`).
    pub exposes: Vec<String>,
    /// Optional SRI of the remote entry.
    pub integrity: String,
    /// Navigation contributions.
    pub nav: Vec<NavEntry>,
}

/// An HTTP route; exactly one of `permission` or `public` must be set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Route {
    /// `GET`, `POST`, `PUT`, `PATCH` or `DELETE`.
    pub method: String,
    /// Path, e.g. `/api/orders/v1/orders/{id}`.
    pub path: String,
    /// `resource:action` (empty only when public).
    pub permission: String,
    /// No permission required.
    pub public: bool,
    /// Body limit (0 = the gateway default).
    pub max_body_bytes: u64,
    /// Upstream timeout (zero = the gateway default).
    pub timeout: Duration,
    /// Ask the gateway to forward the client IP as `X-Gateway-Client-Addr`.
    pub client_address: bool,
}

impl Route {
    /// A route requiring `permission`.
    pub fn protected(method: &str, path: &str, permission: &str) -> Self {
        Self {
            method: method.to_owned(),
            path: path.to_owned(),
            permission: permission.to_owned(),
            ..Self::default()
        }
    }

    /// A public route.
    pub fn public(method: &str, path: &str) -> Self {
        Self {
            method: method.to_owned(),
            path: path.to_owned(),
            public: true,
            ..Self::default()
        }
    }
}

/// A gRPC method; exactly one of `permission` or `public` must be set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Method {
    /// `/pkg.Service/Method`.
    pub full_method: String,
    /// `resource:action` (empty only when public).
    pub permission: String,
    /// No permission required.
    pub public: bool,
    /// Server or bidi streaming.
    pub streaming: bool,
    /// Stream duration cap (zero = gateway default).
    pub max_stream_duration: Duration,
}

/// An API permission (`resource:action`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Permission {
    /// Resource, e.g. `orders`.
    pub resource: String,
    /// Action, e.g. `read`.
    pub action: String,
    /// Description shown to administrators.
    pub description: String,
}

impl Permission {
    /// The `resource:action` reference.
    pub fn reference(&self) -> String {
        perm(&self.resource, &self.action)
    }
}

/// A CASL rule bound to an API permission.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Ability {
    /// CASL actions.
    pub action: Vec<String>,
    /// CASL subjects.
    pub subject: Vec<String>,
    /// Restricted fields.
    pub fields: Vec<String>,
    /// MongoDB-style conditions (operators `$eq $ne $in $nin $lt $lte $gt
    /// $gte $exists`; at most 4096 bytes serialised).
    pub conditions: Map<String, Value>,
    /// A "cannot" rule.
    pub inverted: bool,
    /// Why (for inverted rules).
    pub reason: String,
    /// `resource:action` the rule requires.
    pub requires: String,
}

/// A navigation contribution.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NavEntry {
    /// Title (1-40 characters).
    pub title: String,
    /// Host path, e.g. `/orders`.
    pub path: String,
    /// Icon name.
    pub icon: String,
    /// Sort order (0-1000).
    pub order: i32,
    /// `resource:action` required to see it.
    pub requires: String,
}

/// Formats a permission reference (gatewayclient `Perm`).
pub fn perm(resource: &str, action: &str) -> String {
    format!("{resource}:{action}")
}

impl Manifest {
    /// A manifest for `module`.
    pub fn new(module: &str, display_name: &str, version: &str) -> Self {
        Self {
            module: module.to_owned(),
            display_name: display_name.to_owned(),
            version: version.to_owned(),
            ..Self::default()
        }
    }

    /// Adds an owned prefix.
    #[must_use]
    pub fn prefix(mut self, p: &str) -> Self {
        self.prefixes.push(p.to_owned());
        self
    }

    /// Adds a route.
    #[must_use]
    pub fn route(mut self, r: Route) -> Self {
        self.routes.push(r);
        self
    }

    /// Adds routes (e.g. from [`openapi::routes`]).
    #[must_use]
    pub fn routes(mut self, r: impl IntoIterator<Item = Route>) -> Self {
        self.routes.extend(r);
        self
    }

    /// Adds a gRPC method.
    #[must_use]
    pub fn method(mut self, m: Method) -> Self {
        self.methods.push(m);
        self
    }

    /// Declares a permission.
    #[must_use]
    pub fn permission(mut self, resource: &str, action: &str, description: &str) -> Self {
        self.permissions.push(Permission {
            resource: resource.to_owned(),
            action: action.to_owned(),
            description: description.to_owned(),
        });
        self
    }

    /// Adds a CASL ability.
    #[must_use]
    pub fn ability(mut self, a: Ability) -> Self {
        self.abilities.push(a);
        self
    }

    /// Sets the Module Federation exposes.
    #[must_use]
    pub fn exposes<I, S>(mut self, e: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.exposes = e.into_iter().map(Into::into).collect();
        self
    }

    /// Adds a navigation entry.
    #[must_use]
    pub fn nav(mut self, n: NavEntry) -> Self {
        self.nav.push(n);
        self
    }

    /// `resource:action` for every declared permission, in order.
    pub fn permission_refs(&self) -> Vec<String> {
        self.permissions.iter().map(Permission::reference).collect()
    }

    /// The wire form (gatewayclient `Manifest.Proto`): the remote entry is
    /// always `/m/<module>/mf-manifest.json`.
    pub fn to_proto(&self) -> Result<pb::Manifest, ManifestError> {
        if self.module.is_empty() {
            return Err(ManifestError("gatewayclient: module name is required".into()));
        }
        Ok(pb::Manifest {
            module: self.module.clone(),
            display_name: self.display_name.clone(),
            version: self.version.clone(),
            prefixes: self.prefixes.clone(),
            routes: self
                .routes
                .iter()
                .map(|r| pb::Route {
                    method: r.method.clone(),
                    path: r.path.clone(),
                    permission: r.permission.clone(),
                    public: r.public,
                    max_body_bytes: r.max_body_bytes,
                    timeout: duration_pb(r.timeout),
                    client_address: r.client_address,
                })
                .collect(),
            methods: self
                .methods
                .iter()
                .map(|m| pb::Method {
                    full_method: m.full_method.clone(),
                    permission: m.permission.clone(),
                    public: m.public,
                    streaming: m.streaming,
                    max_stream_duration: duration_pb(m.max_stream_duration),
                })
                .collect(),
            permissions: self
                .permissions
                .iter()
                .map(|p| pb::Permission {
                    resource: p.resource.clone(),
                    action: p.action.clone(),
                    description: p.description.clone(),
                })
                .collect(),
            abilities: self
                .abilities
                .iter()
                .map(|a| pb::Ability {
                    action: a.action.clone(),
                    subject: a.subject.clone(),
                    fields: a.fields.clone(),
                    conditions: (!a.conditions.is_empty()).then(|| struct_pb(&a.conditions)),
                    inverted: a.inverted,
                    reason: a.reason.clone(),
                    requires: a.requires.clone(),
                })
                .collect(),
            remote: Some(pb::Remote {
                entry: format!("/m/{}/mf-manifest.json", self.module),
                exposes: self.exposes.clone(),
                integrity: self.integrity.clone(),
            }),
            nav: self
                .nav
                .iter()
                .map(|n| pb::NavEntry {
                    title: n.title.clone(),
                    path: n.path.clone(),
                    icon: n.icon.clone(),
                    order: n.order,
                    requires: n.requires.clone(),
                })
                .collect(),
        })
    }

    /// Applies the gateway's validation to the wire form.
    pub fn validate(&self) -> Result<GatewayManifest, ManifestError> {
        validate(&self.to_proto()?)
    }

    /// The gateway's content hash of this manifest (portal
    /// `registry.hashManifest`): the same version with a different hash is
    /// refused as `manifest_drift`.
    pub fn content_hash(&self) -> Result<String, ManifestError> {
        Ok(self.validate()?.content_hash())
    }
}

/// durationpb.New for a positive duration; zero is omitted (Go: `if d > 0`).
fn duration_pb(d: Duration) -> Option<prost_types::Duration> {
    if d.is_zero() {
        return None;
    }
    Some(prost_types::Duration {
        seconds: i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
        nanos: i32::try_from(d.subsec_nanos()).unwrap_or(0),
    })
}

/// structpb.NewStruct.
fn struct_pb(m: &Map<String, Value>) -> prost_types::Struct {
    prost_types::Struct {
        fields: m.iter().map(|(k, v)| (k.clone(), value_pb(v))).collect(),
    }
}

fn value_pb(v: &Value) -> prost_types::Value {
    use prost_types::value::Kind;
    let kind = match v {
        Value::Null => Kind::NullValue(0),
        Value::Bool(b) => Kind::BoolValue(*b),
        Value::Number(n) => Kind::NumberValue(n.as_f64().unwrap_or(0.0)),
        Value::String(s) => Kind::StringValue(s.clone()),
        Value::Array(a) => Kind::ListValue(prost_types::ListValue {
            values: a.iter().map(value_pb).collect(),
        }),
        Value::Object(o) => Kind::StructValue(struct_pb(o)),
    };
    prost_types::Value { kind: Some(kind) }
}

#[cfg(test)]
mod tests;
