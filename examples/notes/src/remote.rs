//! The built module-federation remote (`ui/dist`), embedded with the cargo
//! feature `ui` (deployer `ui/embed.go`, Go build tag `ui`). Without the
//! feature, or when `ui/dist` was not built before compiling, the module
//! serves no remote; the gateway then has no UI to load for it.

/// The embedded remote, if this build has one.
#[cfg(feature = "ui")]
pub fn remote() -> Option<tangra_sdk::ui::Remote> {
    static DIST: include_dir::Dir<'static> = include_dir::include_dir!("$NOTES_UI_DIST");
    tangra_sdk::ui::Remote::from_embedded(&DIST).ok()
}
