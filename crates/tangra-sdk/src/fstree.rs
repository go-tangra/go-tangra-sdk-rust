//! A read-only file tree (Go `io/fs.FS`) for content a module ships: its
//! help pages (`docs/help`) and its built UI remote (`ui/dist`).
//!
//! A tree comes from a directory on disk ([`FileTree::from_dir`]), from a
//! directory embedded at compile time with the [`include_dir`] crate
//! ([`FileTree::from_embedded`], the counterpart of Go's `//go:embed
//! all:help`), or is built in memory ([`FileTree::insert`]).
//!
//! `include_dir` is used rather than `rust-embed` because it always embeds
//! (debug builds included; `rust-embed` reads from disk in debug builds
//! unless a feature is set), exposes the tree with its directories like
//! `embed.FS`, needs no derive and no runtime state. A module embeds with:
//!
//! ```ignore
//! static HELP: include_dir::Dir<'static> = include_dir::include_dir!("$CARGO_MANIFEST_DIR/docs/help");
//! let tree = tangra_sdk::fstree::FileTree::from_embedded(&HELP);
//! ```
//!
//! (`include_dir!` expands to paths of the `include_dir` crate, so the module
//! depends on it directly; [`tangra_sdk::include_dir`](crate::include_dir)
//! re-exports the version the SDK accepts.)

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use bytes::Bytes;

/// One file of a [`FileTree`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    /// The content (empty for a non-regular file).
    pub data: Bytes,
    /// False for symlinks and other non-regular files (Go
    /// `DirEntry.Type().IsRegular()`); the loaders refuse them.
    pub regular: bool,
}

/// An immutable tree of files keyed by slash-separated relative path
/// (`guides/setup.md`), with the directories that hold them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileTree {
    files: BTreeMap<String, FileEntry>,
    dirs: BTreeSet<String>,
}

impl FileTree {
    /// An empty tree.
    pub fn new() -> Self {
        Self::default()
    }

    fn add_parents(&mut self, path: &str) {
        let mut p = path;
        while let Some(i) = p.rfind('/') {
            p = &p[..i];
            self.dirs.insert(p.to_owned());
        }
    }

    /// Adds (or replaces) a regular file. `path` is relative, `/`-separated.
    pub fn insert(&mut self, path: impl Into<String>, data: impl Into<Bytes>) -> &mut Self {
        let path = path.into();
        self.add_parents(&path);
        self.files.insert(
            path,
            FileEntry {
                data: data.into(),
                regular: true,
            },
        );
        self
    }

    /// Adds a non-regular entry (a symlink on disk).
    pub fn insert_irregular(&mut self, path: impl Into<String>) -> &mut Self {
        let path = path.into();
        self.add_parents(&path);
        self.files.insert(
            path,
            FileEntry {
                data: Bytes::new(),
                regular: false,
            },
        );
        self
    }

    /// Adds an (empty) directory.
    pub fn insert_dir(&mut self, path: impl Into<String>) -> &mut Self {
        let path = path.into();
        self.add_parents(&path);
        self.dirs.insert(path);
        self
    }

    /// Reads a directory recursively (Go `os.DirFS`). Symlinks are recorded,
    /// not followed, and count as non-regular files. A missing directory is
    /// `ErrorKind::NotFound`.
    pub fn from_dir(root: impl AsRef<Path>) -> std::io::Result<Self> {
        let root = root.as_ref();
        let meta = std::fs::metadata(root)?;
        if !meta.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("{}: not a directory", root.display()),
            ));
        }
        let mut t = Self::new();
        t.read_dir(root, "")?;
        Ok(t)
    }

    fn read_dir(&mut self, dir: &Path, prefix: &str) -> std::io::Result<()> {
        for ent in std::fs::read_dir(dir)? {
            let ent = ent?;
            let name = ent.file_name().to_string_lossy().into_owned();
            let rel = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            let ft = ent.file_type()?;
            if ft.is_dir() {
                self.insert_dir(rel.clone());
                self.read_dir(&ent.path(), &rel)?;
            } else if ft.is_file() {
                let data = std::fs::read(ent.path())?;
                self.insert(rel, data);
            } else {
                self.insert_irregular(rel);
            }
        }
        Ok(())
    }

    /// The tree embedded with `include_dir!` (no copy of the contents).
    pub fn from_embedded(dir: &'static include_dir::Dir<'static>) -> Self {
        let mut t = Self::new();
        t.add_embedded(dir, dir.path());
        t
    }

    fn add_embedded(&mut self, dir: &'static include_dir::Dir<'static>, root: &Path) {
        let rel = |p: &Path| -> String {
            let p = p.strip_prefix(root).unwrap_or(p);
            p.components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/")
        };
        for e in dir.entries() {
            match e {
                include_dir::DirEntry::Dir(d) => {
                    self.insert_dir(rel(d.path()));
                    self.add_embedded(d, root);
                }
                include_dir::DirEntry::File(f) => {
                    self.insert(rel(f.path()), Bytes::from_static(f.contents()));
                }
            }
        }
    }

    /// The sub-tree under `dir` (Go `fs.Sub`); empty when absent.
    #[must_use]
    pub fn sub(&self, dir: &str) -> Self {
        let prefix = format!("{}/", dir.trim_end_matches('/'));
        let mut t = Self::new();
        for (p, e) in &self.files {
            if let Some(r) = p.strip_prefix(&prefix) {
                t.add_parents(r);
                t.files.insert(r.to_owned(), e.clone());
            }
        }
        for d in &self.dirs {
            if let Some(r) = d.strip_prefix(&prefix) {
                t.dirs.insert(r.to_owned());
            }
        }
        t
    }

    /// No files.
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// The number of files.
    pub fn len(&self) -> usize {
        self.files.len()
    }

    /// The file at `path`.
    pub fn get(&self, path: &str) -> Option<&FileEntry> {
        self.files.get(path)
    }

    /// Whether `path` is a directory of the tree (`.` is the root).
    pub fn is_dir(&self, path: &str) -> bool {
        path == "." || self.dirs.contains(path)
    }

    /// The files in `fs.WalkDir` order: depth-first, each directory's
    /// entries sorted by name.
    pub fn walk(&self) -> Vec<(&str, &FileEntry)> {
        let mut v: Vec<(&str, &FileEntry)> = self.files.iter().map(|(p, e)| (p.as_str(), e)).collect();
        v.sort_by(|a, b| walk_order(a.0, b.0));
        v
    }
}

/// Orders two paths as `fs.WalkDir` visits them.
fn walk_order(a: &str, b: &str) -> Ordering {
    let mut x = a.split('/');
    let mut y = b.split('/');
    loop {
        match (x.next(), y.next()) {
            (Some(p), Some(q)) if p == q => {}
            (Some(p), Some(q)) => return p.cmp(q),
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn walk_order_is_per_directory() {
        let mut t = FileTree::new();
        t.insert("a-c.md", "x")
            .insert("a/b.md", "y")
            .insert("index.md", "z");
        let order: Vec<&str> = t.walk().into_iter().map(|(p, _)| p).collect();
        assert_eq!(order, ["a/b.md", "a-c.md", "index.md"]);
        assert!(t.is_dir("a") && t.is_dir(".") && !t.is_dir("a/b.md"));
        let s = t.sub("a");
        assert_eq!(s.get("b.md").map(|e| e.data.clone()), Some(Bytes::from("y")));
    }

    #[test]
    fn from_dir_records_symlinks() {
        let d = tempfile::tempdir().expect("dir");
        std::fs::create_dir_all(d.path().join("sub/empty")).expect("mkdir");
        std::fs::write(d.path().join("sub/a.md"), "a").expect("write");
        #[cfg(unix)]
        std::os::unix::fs::symlink(d.path().join("sub/a.md"), d.path().join("link.md")).expect("symlink");
        let t = FileTree::from_dir(d.path()).expect("tree");
        assert!(t.get("sub/a.md").is_some_and(|e| e.regular));
        assert!(t.is_dir("sub/empty"));
        #[cfg(unix)]
        assert!(t.get("link.md").is_some_and(|e| !e.regular));
        let missing = FileTree::from_dir(d.path().join("nope"));
        assert!(missing.is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound));
    }
}
