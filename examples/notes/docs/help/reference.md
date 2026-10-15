---
title: Reference
summary: Note fields, permissions, roles, API routes and limits.
kind: reference
order: 60
tags: [notes, reference, permissions, api, limits]
---
## Note fields

| Field | Meaning |
|---|---|
| `id` | note ID |
| `title` | 1–200 characters, no control characters |
| `body` | up to 10,000 characters |
| `author_id` | the user who wrote it |
| `created_at`, `updated_at` | timestamps (RFC 3339) |

## Permissions

| Permission | Allows |
|---|---|
| `notes:read` | list and read the tenant's notes |
| `notes:write` | write notes and remove your own |
| `notes:admin` | remove anyone's notes |

## Roles

| Role | Permissions |
|---|---|
| Notes editor | `notes:read`, `notes:write` |
| Notes moderator | all three |
| owner, admin (built-in) | all three |
| member (built-in) | `notes:read`, `notes:write` |
| auditor, operator (built-in) | `notes:read` |

## API

All routes are under `/api/notes/v1` and go through the gateway.

| Route | Permission |
|---|---|
| `GET /info` | none |
| `GET /notes` | `notes:read` |
| `POST /notes` | `notes:write` |
| `GET /notes/{id}` | `notes:read` |
| `POST /notes/{id}/remove` | `notes:write` (+ `notes:admin` for other authors) |

`GET /notes` takes `page`, `page_size` (1–200, default 25), `sort`
(`title`, `created_at`, `updated_at`; default `created_at`), `order`
(`asc`, `desc`) and `q` (title text, up to 100 characters). An invalid value
answers `422` with `detail.param` naming the parameter.

## Events

Each new note publishes `notes.created` with its `id` and `author_id` to
everyone in the tenant. The content is never part of the event.
