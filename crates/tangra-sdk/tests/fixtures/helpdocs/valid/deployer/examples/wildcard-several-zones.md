---
title: "Example: one Cloudflare token, several zones"
summary: Share one Cloudflare configuration between two targets, each supplying its own zone, so the wildcard certificate of each domain renews into the right zone.
kind: example
order: 50
tags: [deployer, example, cloudflare, wildcard, auto-deploy, overrides]
requires: targets:manage
---
**Goal.** Your company has two domains on Cloudflare, `example.com` and
`example.net`. lcm issues a wildcard certificate for each. Whenever either
certificate is issued or renewed, it should be uploaded to its own zone,
without anyone clicking **Deploy**. You have one Cloudflare API token that
may edit SSL certificates in both zones.

**Plan.** One Cloudflare configuration holds the token and leaves the
**Zone ID** to its targets. Two targets, one per domain, each match their
wildcard certificate and supply their zone.

## 1. The shared configuration

In **Deployer → Configurations**, create:

| Field | Value |
|---|---|
| Name | `cloudflare-main` |
| Provider | Cloudflare |
| Zone ID | *(empty)* |
| API token | the token (permission Zone → SSL and Certificates → Edit) |

Choose **Check settings**. Because the zone is missing, the answer is
"Checked. Not tested here: Zone ID — each target supplies it." Save. In the
list, **Deploy** is disabled for this configuration: it can only be deployed
through a target.

## 2. Two targets

Create two targets in **Deployer → Targets**, each with
**Auto-deploy on issue/renewal** on and `cloudflare-main` attached:

| Target | Common name (regex) | Zone ID under **Settings per configuration** |
|---|---|---|
| `example-com` | `*.example.com` | zone ID of example.com |
| `example-net` | `*.example.net` | zone ID of example.net |

`*.example.com` matches the wildcard certificate itself (its common name is
`*.example.com`) and any single-label name such as `www.example.com`, but not
the `example.net` certificate. Each certificate therefore reaches exactly one
target.

The same through the API. Create the target with
`POST /api/deployer/v1/targets`:

```json
{
  "name": "example-com",
  "auto_deploy": true,
  "certificate_filters": [{"common_name_pattern": "*.example.com"}]
}
```

Then attach the configuration and supply the zone (a 32-character hex
string) with `POST /api/deployer/v1/targets/<target id>/configurations`:

```json
{
  "configuration_ids": ["<cloudflare-main id>"],
  "config_overrides": {
    "<cloudflare-main id>": {"zone_id": "023e105f4ecef8ad9ca31a8372d0c353"}
  }
}
```

## 3. What happens on renewal

When lcm renews `*.example.com`, the deployer creates a parent job for
`example-com` with one child job for `cloudflare-main`, triggered
`auto_renewal`. The child deploys with the token from `cloudflare-main` and
the zone from `example-com`. The `example-net` target does not match and
creates no job.

On **Deployer → Jobs** you see:

| Type | Trigger | Status |
|---|---|---|
| parent | `auto_renewal` | `completed` |
| child | `auto_renewal` | `completed` |

## Variations

- **Add another endpoint.** Attach a second configuration (for example a
  FortiGate) to `example-com`. The next renewal creates two children; if one
  fails, the parent becomes `partial`. See [jobs](../guides/jobs.md).
- **Rotate the token.** Edit `cloudflare-main` and type the new token. Both
  targets use it from the next deployment on.
- **Forgot the zone?** A target that attaches `cloudflare-main` without a
  zone shows "Missing required values: Zone ID", and its jobs fail with
  `configuration incomplete: Zone ID must be provided by the target`.

Related: [auto-deploy](../guides/auto-deploy.md),
[configurations](../guides/configurations.md).
