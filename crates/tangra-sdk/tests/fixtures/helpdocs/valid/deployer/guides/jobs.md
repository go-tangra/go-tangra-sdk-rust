---
title: Follow, retry, verify and roll back jobs
summary: Read job status and history, understand automatic retries, and retry, cancel, verify or roll back a deployment.
kind: guide
order: 40
tags: [deployer, jobs, retry, rollback, verify, troubleshooting]
requires: jobs:read
---
Every deployment is a job. Open **Deployer → Jobs** to see them, newest
first. The list updates live: you do not need to refresh. You can filter it
by status and job type.

## Job types

- **direct** — one certificate to one configuration (the **Deploy** button).
- **parent** — one certificate to a target. It does not deploy anything
  itself; it shows the combined outcome of its children.
- **child** — the part of a parent job for one attached configuration.

A parent is `completed` when all children completed, `failed` when all
failed, and `partial` when some failed. Its progress is the share of
children that finished.

## Read a job

Open a job to see:

- **Certificate** and **Serial** of the deployed certificate;
- **Retries**, as used / allowed, for example `1 / 3`;
- **Message**, the latest progress note;
- the error of the last failure (titled **Deployment failed** while the job
  is failed). It is the provider's or lcm's own message, with credentials
  removed, so it usually names the real cause;
- **History**: every deploy, verify and rollback attempt with its result and
  duration;
- **Child deployments** for a parent job;
- **Hosts** for the Inventory agent provider: the state each host reported.

## Automatic retries

When a deployment fails, the job goes to `retrying` and runs again after a
delay that grows each time (by default 1, 2, then 4 minutes). After the last
retry the job is `failed`. Some failures are not retried because retrying
cannot help, for example:

- `configuration incomplete: … must be provided by the target` — a required
  value is missing; fill it in on the configuration or the target;
- `certificate has no stored private key` — lcm holds no key for this
  certificate, and the provider needs one;
- `credentials unavailable` — the stored credentials could not be opened;
- `no hosts matched` — the Inventory agent selection matches no host;
- a FortiGate `MANUAL REVIEW REQUIRED` stop.

## Actions

The buttons in the job drawer need `jobs:manage` (Cancel, Retry) or
`deploy:execute` (Verify, Rollback).

| Action | Shown for | Effect |
|---|---|---|
| **Cancel** | `pending`, `processing`, `retrying` | marks the job `cancelled`; for a parent, also its unfinished children |
| **Retry** | `failed`, `partial` | queues the job again, if it has retries left |
| **Verify** | direct and child jobs | asks the endpoint whether the certificate is installed; adds a `verify` history entry |
| **Rollback** | direct and child jobs | asks the provider to undo the deployment; adds a `rollback` history entry |

Notes:

- A parent job only sums up its children. To run a partial deployment again,
  open each failed child and retry it.
- Retry does nothing once all retries are used up (`3 / 3`). Through the API,
  `POST /api/deployer/v1/jobs/<id>/retry?force=true` resets the count and
  queues the job again.
- Verify and Rollback on a provider without that capability answer
  `409 unsupported`. AWS Certificate Manager, Cloudflare and Inventory agent
  have no rollback. See [providers](../index.md#providers).

## Simulate a failure

To see retries and errors without touching real infrastructure, edit a
**Dummy** configuration, turn on **Fail** and deploy to it.

## Who sees job events

Live job updates go only to users who hold `jobs:read`. Users without it do
not see the Jobs page and receive no job events.
