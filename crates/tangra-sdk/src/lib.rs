//! Build go-tangra v4 modules in Rust with the same wire behaviour as Go
//! modules built on `github.com/go-tangra/go-tangra/v4` (freya).
//!
//! Every protocol detail is ported from the Go sources; module docs cite the
//! Go file each behaviour comes from.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

pub mod admin;
pub mod app;
pub mod audit;
pub mod catalogue;
pub mod config;
pub mod correlation;
pub mod error;
pub mod fstree;
pub mod helpdocs;
pub mod identity;
pub mod listquery;
pub mod log;
pub mod policy;
pub mod testutil;
pub mod tls;
#[cfg(feature = "ui")]
pub mod ui;

mod gocompat;
mod gofmt;
mod goyaml;
mod net;

pub use gofmt::GoDuration;
/// The `include_dir` crate the SDK's embedded trees ([`fstree::FileTree::from_embedded`]) accept.
pub use include_dir;
