---
title: Deploy automatically on issue and renewal
summary: Use a target with certificate filters and auto-deploy so new and renewed certificates install themselves.
kind: guide
order: 30
tags: [deployer, targets, auto-deploy, filters, renewal]
requires: targets:read
---
A **target** groups configurations. With **auto-deploy** on, the deployer
watches lcm: whenever lcm issues or renews a certificate that matches one of
the target's filters, it deploys that certificate to every configuration
attached to the target. No one has to click **Deploy** when a certificate
renews.

Creating and changing targets needs `targets:manage`.

## Create a target

1. Open **Deployer → Targets** and choose **New target**.
2. Enter a **Name** and, optionally, a **Description**.
3. Turn on **Auto-deploy on issue/renewal**.
4. Under **Certificate filters**, choose **Add filter** and fill in the
   fields you want to match (see below).
5. Under **Attached configurations**, tick the configurations to deploy to.
6. If a configuration needs values from this target, open it under
   **Settings per configuration** and fill them in.
7. Choose **Save**.

## How filters match

Each filter has these fields. Empty fields are ignored.

| Field | Matches | How |
|---|---|---|
| Issuer (exact) | the certificate's issuer name | exact text |
| Common name (regex) | the subject common name | pattern |
| SAN (regex) | any one of the subject alternative names | pattern |
| Organization (exact) | the subject O | exact text |

Through the API a filter can also match `subject_org_unit` and
`subject_country`, both exact.

- All filled fields of one filter must match (AND).
- A target with several filters deploys when **any** filter matches (OR).
- A target with **no** filters, or with an empty filter, matches every
  certificate. Be careful with auto-deploy on such a target.

A pattern is either:

- a leading-wildcard name such as `*.example.com`, which matches exactly one
  label in front of the domain: `www.example.com` and `*.example.com` match,
  `a.b.example.com` and `example.com` do not; or
- a regular expression (RE2 syntax), always matched against the whole value:
  `api\.example\.(com|net)` matches `api.example.com` but not
  `api.example.com.evil.net`.

A pattern that is not a valid expression is matched as plain text. A
pattern longer than 256 characters never matches.

## What happens on an event

When lcm publishes `certificate.issued` or `certificate.renewed`, the
deployer fetches the certificate and checks every target with auto-deploy on.
For each matching target that has at least one attached configuration it
creates a **parent** job with one **child** job per configuration. The jobs
are triggered `event` for a new certificate and `auto_renewal` for a renewal.
Follow them on the [Jobs](jobs.md) page.

Certificates issued while the deployer is not running are not replayed when
it starts again: deploy those by hand.

## Supply or change settings per target

Under **Settings per configuration**, each attached configuration shows the
fields its provider lets a target change. Leave a field empty to inherit the
configuration's value. A **Must supply** badge marks fields the configuration
left for its targets; deployments to the target fail until they are filled.

Overrides never carry credentials, and fields that decide where credentials
go (URLs, the appliance host) are never overridable. See
[target overrides](../reference.md#target-overrides).

## Deploy to a target by hand

The portal deploys by hand to one configuration at a time. To deploy a
certificate to every configuration of a target at once, call the API with the
`deploy:execute` permission: `POST /api/deployer/v1/deploy/target` with
the `X-CSRF-Token` header and this JSON body:

```json
{"certificate_id": "<lcm certificate id>", "target_id": "<target id>"}
```

The answer is `202` with the parent `job_id`. A target with no attached
configurations is refused with `422 validation_failed`.
