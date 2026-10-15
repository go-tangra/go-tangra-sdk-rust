//! `notes`: a small but complete go-tangra v4 module written with the Rust
//! SDK, structured like the Go reference module (go-tangra-deployer):
//!
//! - [`config`]: framework keys + module sections, strict YAML;
//! - [`manifest`]: permissions, roles, grants, abilities, nav and the
//!   gateway manifest derived from `api/openapi/notes.yaml`;
//! - [`module`]: the wiring (identity, App, verifier, auth registration,
//!   gateway lease, event bus, HTTP);
//! - [`api`]: the tenant-scoped HTTP API;
//! - [`store`]: in-memory storage (a real module uses PostgreSQL);
//! - [`docs`] and `remote` (feature `ui`): the embedded help pages and UI
//!   remote.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

pub mod api;
pub mod config;
pub mod docs;
pub mod healthcheck;
pub mod manifest;
pub mod module;
#[cfg(feature = "ui")]
pub mod remote;
pub mod store;

/// The release, reported to the gateway as the build version: the
/// `NOTES_VERSION` the image build stamps (Go: `-ldflags -X main.version`),
/// else the crate version.
pub const VERSION: &str = match option_env!("NOTES_VERSION") {
    Some(v) => v,
    None => env!("CARGO_PKG_VERSION"),
};
