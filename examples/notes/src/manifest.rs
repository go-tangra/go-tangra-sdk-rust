//! What the notes module registers with the gateway and with auth (the
//! deployer's `pkg/deployermanifest`): routes derived from the embedded
//! OpenAPI document, the API permissions, CASL abilities, navigation, module
//! roles and built-in role grants.
//!
//! Bump [`VERSION`] on every manifest change: the gateway refuses changed
//! content under an unchanged version (`manifest_drift`); the test
//! `manifest_version_pinned` fails until you do.

use std::collections::BTreeMap;

use tangra_sdk::auth::{self, ModuleRole, Registration};
use tangra_sdk::manifest::{self, Ability, Manifest, ManifestError, NavEntry, Permission};

/// Module (and service) name.
pub const MODULE: &str = "notes";
/// Shown in the portal.
pub const DISPLAY_NAME: &str = "Notes";
/// Manifest version: bump on every manifest change (pinned in
/// `testdata/manifest.sha256`).
pub const VERSION: &str = "1.0.0";
/// The owned API prefix.
pub const PREFIX: &str = "/api/notes";
/// The module-federation exposes (`ui/module-federation.config.ts`).
pub const EXPOSES: [&str; 3] = ["./routes", "./nav", "./boot"];

/// The OpenAPI contract the routes are derived from.
pub const OPENAPI: &[u8] = include_bytes!("../api/openapi/notes.yaml");

/// The API permissions.
pub fn permissions() -> Vec<Permission> {
    [
        ("read", "List and read the tenant's notes"),
        ("write", "Create notes and remove your own"),
        ("admin", "Remove any author's notes"),
    ]
    .into_iter()
    .map(|(action, description)| Permission {
        resource: "notes".into(),
        action: action.into(),
        description: description.into(),
    })
    .collect()
}

/// `resource:action` of every permission (also the catalogue entry's list).
pub fn permission_refs() -> Vec<String> {
    permissions().iter().map(Permission::reference).collect()
}

/// Built-in role grants. The complete set: a grant withdrawn here is
/// revoked from existing tenants' built-in roles.
pub fn grants() -> BTreeMap<String, Vec<String>> {
    let all = permission_refs();
    BTreeMap::from([
        ("owner".to_owned(), all.clone()),
        ("admin".to_owned(), all),
        (
            "member".to_owned(),
            vec!["notes:read".into(), "notes:write".into()],
        ),
        ("auditor".to_owned(), vec!["notes:read".into()]),
        ("operator".to_owned(), vec!["notes:read".into()]),
    ])
}

/// Module roles auth provides in every tenant.
pub fn roles() -> Vec<ModuleRole> {
    vec![
        ModuleRole {
            slug: "editor".into(),
            display_name: format!("{DISPLAY_NAME} editor"),
            description: "Read and write notes, remove your own".into(),
            permissions: vec!["notes:read".into(), "notes:write".into()],
        },
        ModuleRole {
            slug: "moderator".into(),
            display_name: format!("{DISPLAY_NAME} moderator"),
            description: "Every notes permission, including removing any author's notes".into(),
            permissions: permission_refs(),
        },
    ]
}

/// CASL rules bound to the permissions (the UI's `can()`).
pub fn abilities() -> Vec<Ability> {
    let rule = |actions: &[&str], requires: &str| Ability {
        action: actions.iter().map(|a| (*a).to_owned()).collect(),
        subject: vec!["Note".into()],
        requires: requires.into(),
        ..Ability::default()
    };
    vec![
        rule(&["read"], "notes:read"),
        rule(&["create"], "notes:write"),
        rule(&["delete"], "notes:admin"),
    ]
}

/// Navigation contributions (icons must be in the `@go-tangra/ui` kit set).
pub fn nav() -> Vec<NavEntry> {
    vec![NavEntry {
        title: "Notes".into(),
        path: "/notes".into(),
        icon: "mdi-file-document-edit-outline".into(),
        order: 500,
        requires: "notes:read".into(),
    }]
}

/// The gateway manifest; the routes come from [`OPENAPI`] (an undeclared
/// permission is an error).
pub fn manifest() -> Result<Manifest, ManifestError> {
    let routes = manifest::openapi::routes(OPENAPI, &permission_refs())?;
    let mut m = Manifest::new(MODULE, DISPLAY_NAME, VERSION)
        .prefix(PREFIX)
        .routes(routes)
        .exposes(EXPOSES);
    m.permissions = permissions();
    m.abilities = abilities();
    m.nav = nav();
    Ok(m)
}

/// What the module registers with auth at start and every five minutes.
pub fn registration() -> Registration {
    Registration {
        module: MODULE.into(),
        display_name: DISPLAY_NAME.into(),
        permissions: permissions()
            .into_iter()
            .map(|p| auth::Permission {
                resource: p.resource,
                action: p.action,
                description: p.description,
            })
            .collect(),
        roles: roles(),
        builtin_grants: grants(),
        declares_grants: true,
        tenant_ids: Vec::new(),
    }
}
