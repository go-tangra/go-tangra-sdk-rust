//! The help pages (`docs/help`), embedded in the binary (deployer
//! `docs/embed.go`). CI lints them with the go-tangra `docs-lint` action;
//! the module refuses to start when they do not load.

use include_dir::{Dir, include_dir};
use tangra_sdk::fstree::FileTree;
use tangra_sdk::helpdocs::{self, Bundle, Problems};

static HELP: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/docs/help");

/// The `docs/help` tree.
pub fn help() -> FileTree {
    FileTree::from_embedded(&HELP)
}

/// The bundle served to the gateway at `/docs/v1/bundle`.
pub fn bundle() -> Result<Bundle, Problems> {
    helpdocs::load(&help(), crate::manifest::MODULE)
}
