---
title: Deployer
summary: Install lcm-issued certificates on cloud services, load balancers, firewalls, webhooks and Linux hosts, by hand or automatically on issue and renewal.
kind: guide
order: 0
tags: [deployer, certificates, overview]
---
The deployer takes certificates issued by **lcm** (the Certificates module) and
installs them on your infrastructure. It can deploy on demand, or
automatically whenever lcm issues or renews a certificate that matches your
rules.

## Concepts

- **Configuration** — one endpoint the deployer can install a certificate on:
  a provider (for example Cloudflare or FortiGate), its settings and its
  credentials. Credentials are encrypted and never shown again after you save
  them.
- **Target** — a named group of configurations, with optional
  **certificate filters** and an **auto-deploy** switch. A target can also
  change some provider settings for each configuration it uses.
- **Job** — one deployment of one certificate. Deploying to a configuration
  creates a *direct* job; deploying to a target creates a *parent* job with one
  *child* job per configuration. Jobs retry on failure and update live in the
  portal.

The deployer never stores certificate bytes. At deploy time it fetches the
certificate, chain and (when the provider needs it) the private key from lcm,
hands them to the provider and drops them.

## Providers

| Provider | Installs on | Verify | Rollback |
|---|---|:-:|:-:|
| AWS Certificate Manager (`aws_acm`) | ACM in one region | yes | no |
| Cloudflare (`cloudflare`) | a Cloudflare zone | yes | no |
| F5 BIG-IP (`bigip`) | a BIG-IP partition, optionally a client-SSL profile | yes | yes |
| FortiGate (`fortigate`) | a FortiGate VDOM and its SSL profiles | yes | yes |
| Webhook (`webhook`) | any HTTP endpoint that accepts a JSON POST | yes | yes |
| Inventory agent (`inventory-agent`) | Linux hosts running the go-tangra-inventory agent | yes | no |
| Dummy (`dummy`) | nothing: for testing | yes | yes |

## Pages in the portal

| Page | Shows | Needs |
|---|---|---|
| Dashboard | jobs by status, recent success rate, recent errors | `stats:read` |
| Targets | deployment targets, filters, attached configurations | `targets:read` |
| Configurations | provider configurations; **Deploy** | `configurations:read` |
| Jobs | deployment jobs, their history and actions | `jobs:read` |

Your role decides what you can do; see [permissions and roles](reference.md#permissions-and-roles).

## Where to go next

- [Get started](getting-started.md): your first deployment in five minutes.
- [Manage configurations](guides/configurations.md)
- [Deploy automatically on issue and renewal](guides/auto-deploy.md)
- [Follow, retry, verify and roll back jobs](guides/jobs.md)
- [Example: one wildcard certificate, several zones](examples/wildcard-several-zones.md)
- [Reference](reference.md): fields, states, triggers and limits.
