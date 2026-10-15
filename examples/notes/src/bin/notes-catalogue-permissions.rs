//! Prints the module's permissions (`resource:action`) as a JSON array for
//! its catalogue entry (spec 035): the `catalogue-entry` action's
//! `permissions-command` (deployer `cmd/deployer-catalogue-permissions`).

fn main() -> std::io::Result<()> {
    tangra_sdk::catalogue::print_permissions(tangra_notes::manifest::permission_refs())
}
