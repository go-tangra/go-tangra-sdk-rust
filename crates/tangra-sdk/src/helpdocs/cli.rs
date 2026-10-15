//! The `tangra-docs` command (go-tangra `cmd/tangra-docs`) as a library
//! function, run by the `tangra-docs-rs` binary:
//!
//! ```text
//! tangra-docs-rs lint [dir]                          (default docs/help)
//! tangra-docs-rs bundle [-module name] [-o file.json] [dir]
//! ```
//!
//! `lint` prints every problem as `file:line: message` (file joined to dir)
//! on stderr and exits 1 when there is any. Output and exit codes match the
//! Go tool, so the `go-tangra/.github/actions/docs-lint` annotations work on
//! either; module CI can keep using the Go action.

use std::io::Write;

use super::{DEFAULT_DIR, Problems, lint, load};
use crate::fstree::FileTree;
use crate::gocompat;

/// Runs the command with `args` (without the program name) and returns the
/// exit code.
pub fn cli(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let Some(cmd) = args.first() else {
        let _ = writeln!(stderr, "usage: tangra-docs lint|bundle [flags] [dir]");
        return 2;
    };
    match cmd.as_str() {
        "lint" => run_lint(&args[1..], stdout, stderr),
        "bundle" => run_bundle(&args[1..], stdout, stderr),
        other => {
            let _ = writeln!(
                stderr,
                "unknown command {} (lint, bundle)",
                gocompat::quote(other)
            );
            2
        }
    }
}

struct Flags {
    module: String,
    out: String,
    dir: String,
}

/// Go `flag` parsing where flags may also follow the directory.
fn parse(args: &[String], allow: &[&str], stderr: &mut dyn Write) -> Option<Flags> {
    let mut f = Flags {
        module: String::new(),
        out: String::new(),
        dir: String::new(),
    };
    let mut dirs = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        let name = a
            .strip_prefix("--")
            .or_else(|| a.strip_prefix('-'))
            .filter(|n| !n.is_empty());
        let Some(name) = name else {
            dirs.push(a.clone());
            i += 1;
            continue;
        };
        let (name, inline) = match name.split_once('=') {
            Some((n, v)) => (n, Some(v.to_owned())),
            None => (name, None),
        };
        if !allow.contains(&name) {
            let _ = writeln!(stderr, "flag provided but not defined: -{name}");
            return None;
        }
        let value = match inline {
            Some(v) => v,
            None => {
                i += 1;
                match args.get(i) {
                    Some(v) => v.clone(),
                    None => {
                        let _ = writeln!(stderr, "flag needs an argument: -{name}");
                        return None;
                    }
                }
            }
        };
        match name {
            "module" => f.module = value,
            _ => f.out = value,
        }
        i += 1;
    }
    if dirs.len() > 1 {
        let _ = writeln!(stderr, "expected at most one directory");
        return None;
    }
    f.dir = dirs.pop().unwrap_or_else(|| DEFAULT_DIR.to_owned());
    if !std::path::Path::new(&f.dir).is_dir() {
        let _ = writeln!(stderr, "{}: not a directory", f.dir);
        return None;
    }
    Some(f)
}

fn report(dir: &str, ps: &Problems, stderr: &mut dyn Write) -> i32 {
    for p in &ps.0 {
        let mut p = p.clone();
        if !p.file.is_empty() {
            p.file = gocompat::join(dir, &p.file);
        }
        let _ = writeln!(stderr, "{p}");
    }
    let _ = writeln!(stderr, "{} problem(s)", ps.0.len());
    1
}

fn tree(dir: &str, stderr: &mut dyn Write) -> Option<FileTree> {
    match FileTree::from_dir(dir) {
        Ok(t) => Some(t),
        Err(e) => {
            let _ = writeln!(stderr, "{dir}: {e}");
            None
        }
    }
}

fn run_lint(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let Some(f) = parse(args, &[], stderr) else {
        return 2;
    };
    let Some(t) = tree(&f.dir, stderr) else {
        return 1;
    };
    match lint(&t) {
        Ok(()) => {
            let _ = writeln!(stdout, "{}: ok", f.dir);
            0
        }
        Err(ps) => report(&f.dir, &ps, stderr),
    }
}

fn run_bundle(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let Some(f) = parse(args, &["module", "o"], stderr) else {
        return 2;
    };
    if f.module.is_empty() {
        let _ = writeln!(stderr, "-module is required");
        return 2;
    }
    let Some(t) = tree(&f.dir, stderr) else {
        return 1;
    };
    let b = match load(&t, &f.module) {
        Ok(b) => b,
        Err(ps) => return report(&f.dir, &ps, stderr),
    };
    let raw = b.marshal();
    if !f.out.is_empty()
        && let Err(e) = std::fs::write(&f.out, &raw)
    {
        let _ = writeln!(stderr, "open {}: {e}", f.out);
        return 1;
    }
    let digest = if b.digest.is_empty() {
        "(empty)"
    } else {
        b.digest.as_str()
    };
    let _ = writeln!(
        stdout,
        "{}: digest {digest}, {} pages, {} images, {} bytes",
        b.module,
        b.pages.len(),
        b.assets.len(),
        raw.len()
    );
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(args: &[&str]) -> (i32, String, String) {
        let args: Vec<String> = args.iter().map(|s| (*s).to_owned()).collect();
        let (mut o, mut e) = (Vec::new(), Vec::new());
        let code = cli(&args, &mut o, &mut e);
        (
            code,
            String::from_utf8_lossy(&o).into_owned(),
            String::from_utf8_lossy(&e).into_owned(),
        )
    }

    #[test]
    fn lint_and_bundle_like_tangra_docs() {
        let root = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/helpdocs");
        let ok = format!("{root}/valid/deployer");
        assert_eq!(run(&["lint", &ok]), (0, format!("{ok}: ok\n"), String::new()));
        let bad = format!("{root}/invalid/dup-slug");
        let (code, _, err) = run(&["lint", &bad]);
        assert_eq!(code, 1);
        assert_eq!(
            err,
            format!("{bad}/a/index.md: duplicate slug \"a\" (also a.md)\n1 problem(s)\n")
        );
        let (code, out, _) = run(&["bundle", &ok, "-module", "deployer"]);
        assert_eq!(code, 0);
        let digest = std::fs::read_to_string(format!("{root}/valid/deployer.digest")).expect("digest");
        assert!(
            out.starts_with(&format!(
                "deployer: digest {}, 8 pages, 0 images, ",
                digest.trim()
            )),
            "{out}"
        );
        assert_eq!(run(&["bundle", &ok]).0, 2);
        assert_eq!(
            run(&["lint", "/nonexistent"]),
            (2, String::new(), "/nonexistent: not a directory\n".into())
        );
        assert_eq!(run(&["frob"]).0, 2);
        assert_eq!(run(&[]).0, 2);
    }
}
