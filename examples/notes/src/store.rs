//! Note storage, scoped by tenant on every call.
//!
//! This example keeps notes in memory so it runs without a database. A real
//! module keeps them in PostgreSQL: `sqlx` with a pool from `db.dsn`
//! (`sslmode=verify-full` in production), migrations embedded with
//! `sqlx::migrate!()` and applied by `bootstrap` (and at start) with
//! `db.migrate_dsn`, the tenant in every `WHERE`, and the list's ORDER BY
//! built by `listquery::Request::order_by` from the spec's constants only.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::SystemTime;

use serde::Serialize;
use tangra_sdk::listquery::{self, Dir, Field, Page, SortKey, Spec};

/// A stored note.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Note {
    /// UUIDv7.
    pub id: String,
    /// Title (1-200 characters).
    pub title: String,
    /// Body (up to 10000 characters).
    pub body: String,
    /// The author's user ID.
    pub author_id: String,
    /// RFC 3339.
    #[serde(serialize_with = "rfc3339")]
    pub created_at: SystemTime,
    /// RFC 3339.
    #[serde(serialize_with = "rfc3339")]
    pub updated_at: SystemTime,
}

fn rfc3339<S: serde::Serializer>(t: &SystemTime, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(
        &chrono::DateTime::<chrono::Utc>::from(*t).to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
    )
}

/// A refused write.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StoreError {
    /// The tenant holds `limits_notes.max_notes_per_tenant` notes.
    #[error("tenant note limit reached")]
    Full,
}

/// The list's sort allow-list (`GET /api/notes/v1/notes`).
pub fn list_spec() -> Spec {
    Spec {
        fields: [
            (
                "title",
                Field {
                    expr: "title",
                    text: true,
                    not_null: true,
                    ..Field::default()
                },
            ),
            (
                "created_at",
                Field {
                    expr: "created_at",
                    default_dir: Some(Dir::Desc),
                    not_null: true,
                    ..Field::default()
                },
            ),
            (
                "updated_at",
                Field {
                    expr: "updated_at",
                    default_dir: Some(Dir::Desc),
                    not_null: true,
                    ..Field::default()
                },
            ),
        ]
        .into_iter()
        .collect(),
        default: "created_at",
        tie_break: "id",
        default_size: 0,
        max_size: 0,
    }
}

/// In-memory notes, per tenant.
#[derive(Debug, Default)]
pub struct Store {
    tenants: RwLock<HashMap<String, Vec<Note>>>,
    max_per_tenant: usize,
}

impl Store {
    /// A store keeping at most `max_per_tenant` notes per tenant.
    pub fn new(max_per_tenant: usize) -> Self {
        Self {
            tenants: RwLock::new(HashMap::new()),
            max_per_tenant,
        }
    }

    /// Adds a note to `tenant`.
    pub fn create(&self, tenant: &str, author: &str, title: &str, body: &str) -> Result<Note, StoreError> {
        let now = SystemTime::now();
        let note = Note {
            id: uuid::Uuid::now_v7().to_string(),
            title: title.to_owned(),
            body: body.to_owned(),
            author_id: author.to_owned(),
            created_at: now,
            updated_at: now,
        };
        let mut t = self
            .tenants
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let notes = t.entry(tenant.to_owned()).or_default();
        if notes.len() >= self.max_per_tenant {
            return Err(StoreError::Full);
        }
        notes.push(note.clone());
        Ok(note)
    }

    /// The note `id` of `tenant` (another tenant's note is `None`).
    pub fn get(&self, tenant: &str, id: &str) -> Option<Note> {
        let t = self
            .tenants
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        t.get(tenant)?.iter().find(|n| n.id == id).cloned()
    }

    /// Removes the note `id` of `tenant`.
    pub fn remove(&self, tenant: &str, id: &str) -> Option<Note> {
        let mut t = self
            .tenants
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let notes = t.get_mut(tenant)?;
        let i = notes.iter().position(|n| n.id == id)?;
        Some(notes.remove(i))
    }

    /// One page of `tenant`'s notes whose title contains `q`
    /// (case-insensitive), ordered as `r` asks (a page beyond the end
    /// answers the last page).
    pub fn list(&self, tenant: &str, q: &str, r: &listquery::Request) -> Page<Note> {
        let q = q.to_lowercase();
        let mut items: Vec<Note> = {
            let t = self
                .tenants
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            t.get(tenant)
                .map(|v| {
                    v.iter()
                        .filter(|n| q.is_empty() || n.title.to_lowercase().contains(&q))
                        .cloned()
                        .collect()
                })
                .unwrap_or_default()
        };
        listquery::sort_slice(
            &mut items,
            r,
            |n, field| match field {
                "title" => SortKey::Str(n.title.clone()),
                "updated_at" => SortKey::Time(n.updated_at),
                _ => SortKey::Time(n.created_at),
            },
            |n| n.id.clone(),
        );
        let (page, total, applied) = listquery::window(&items, r);
        Page::new(page.to_vec(), total, &applied)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_scoped_sorted_and_limited() {
        let s = Store::new(3);
        let spec = list_spec();
        spec.validate().unwrap();
        let a = s.create("t1", "u1", "beta", "").unwrap();
        let b = s.create("t1", "u1", "Alpha", "").unwrap();
        s.create("t2", "u2", "gamma", "").unwrap();
        assert_eq!(s.get("t2", &a.id), None, "another tenant's note is invisible");
        let by_title = listquery::new(0, 0, "title", None, &spec).unwrap();
        let p = s.list("t1", "", &by_title);
        assert_eq!(p.total, 2);
        assert_eq!(p.items[0].id, b.id, "case-insensitive title order");
        let newest = listquery::new(0, 0, "", None, &spec).unwrap();
        assert_eq!(newest.order, Dir::Desc);
        assert_eq!(s.list("t1", "ALP", &newest).items.len(), 1);
        s.create("t1", "u1", "c", "").unwrap();
        assert_eq!(s.create("t1", "u1", "d", ""), Err(StoreError::Full));
        assert!(s.remove("t2", &a.id).is_none());
        assert_eq!(s.remove("t1", &a.id).map(|n| n.id), Some(a.id));
    }
}
