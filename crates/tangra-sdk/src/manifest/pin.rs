//! Version pinning for a module's manifest (the deployer's
//! `TestManifestVersionPinned`, `pkg/deployermanifest/version_test.go`).
//!
//! The gateway keeps one manifest per module and accepts a different one
//! only under a higher version; the same version with changed content is
//! refused (`manifest_drift`) until every old instance's lease expires. A
//! pin file (`"<version> <sha256>"`) ties the content to the version, so a
//! test fails when the manifest changes without a version bump.
//!
//! The hash is the gateway's own content hash ([`super::Manifest::content_hash`],
//! portal `registry.hashManifest`), not the Go deployer's hash of its Go
//! struct, so a Rust module's pin is exactly what the gateway compares.
//!
//! ```no_run
//! # fn manifest() -> tangra_sdk::manifest::Manifest { unimplemented!() }
//! // In a #[test]:
//! fn manifest_version_pinned() {
//!     // Refresh after bumping the version:
//!     //   TANGRA_UPDATE_MANIFEST_PIN=1 cargo test manifest_version_pinned
//!     tangra_sdk::manifest::pin::check(&manifest(), "testdata/manifest.sha256").unwrap();
//! }
//! ```

use std::path::Path;

use super::Manifest;

/// Set (to anything) to rewrite the pin file instead of checking it.
pub const UPDATE_ENV: &str = "TANGRA_UPDATE_MANIFEST_PIN";

/// The pin line for `m`: `"<version> <content hash>"`.
pub fn line(m: &Manifest) -> Result<String, String> {
    let hash = m.content_hash().map_err(|e| e.to_string())?;
    Ok(format!("{} {hash}", m.version))
}

/// Checks `m` against the pin file (or rewrites it when [`UPDATE_ENV`] is
/// set). The errors say what to do, like the deployer's test.
pub fn check(m: &Manifest, pin_file: impl AsRef<Path>) -> Result<(), String> {
    let path = pin_file.as_ref();
    let got = line(m)?;
    if std::env::var_os(UPDATE_ENV).is_some() {
        if let Some(dir) = path.parent()
            && !dir.as_os_str().is_empty()
        {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
        return std::fs::write(path, format!("{got}\n")).map_err(|e| e.to_string());
    }
    let want = std::fs::read_to_string(path)
        .map_err(|e| format!("{e} (rerun with {UPDATE_ENV}=1)"))?
        .trim()
        .to_owned();
    let pinned_version = want.split_once(' ').map_or(want.as_str(), |(v, _)| v);
    if got == want {
        Ok(())
    } else if pinned_version == m.version {
        Err(format!(
            "the manifest changed but its version is still {}: bump the version, then rerun with {UPDATE_ENV}=1",
            m.version
        ))
    } else {
        Err(format!(
            "version bumped to {}: refresh the pin by rerunning with {UPDATE_ENV}=1",
            m.version
        ))
    }
}
