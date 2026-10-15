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
pub mod auth;
pub mod config;
pub mod correlation;
pub mod error;
pub mod gateway;
pub mod identity;
pub mod listquery;
pub mod log;
pub mod manifest;
pub mod policy;
pub mod testutil;
pub mod tls;

mod gofmt;
mod net;

pub use gofmt::GoDuration;
