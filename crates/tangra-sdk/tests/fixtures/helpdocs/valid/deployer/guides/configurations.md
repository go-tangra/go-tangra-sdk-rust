---
title: Manage configurations
summary: Add a provider configuration, test its connection, keep credentials safe and leave settings for targets to supply.
kind: guide
order: 20
tags: [deployer, configurations, providers, credentials]
requires: configurations:read
---
A configuration is one endpoint the deployer can install certificates on: a
provider, its settings and its credentials. Everyone with
`configurations:read` can list and open configurations; creating, changing,
testing and deleting them needs `configurations:manage`.

## Create a configuration

1. Open **Deployer → Configurations** and choose **New configuration**.
2. Enter a **Name** (up to 100 characters) and, optionally, a
   **Description**.
3. Choose the **Provider**. The drawer shows that provider's fields in three
   groups: **Connection**, **Credentials** and **Options**. Required fields
   are marked, and defaults are filled in.
4. Run the provider's check (see below), then choose **Save**.

The provider cannot be changed after saving. To move an endpoint to another
provider, create a new configuration.

## Test before you save

Each provider has one check button in the drawer:

| Button | Providers | What it does |
|---|---|---|
| **Test connection** | F5 BIG-IP, FortiGate, Webhook | contacts the endpoint with the entered credentials |
| **Check settings** | AWS Certificate Manager, Cloudflare, Dummy | checks the values without deploying anything |
| **Preview hosts** | Inventory agent | lists the hosts the selection matches and whether their agents can receive certificates |

"Connection successful." means the endpoint accepted the credentials. If the
endpoint refuses them, the check fails with `credentials_rejected` and
nothing is saved.

## Credentials are write-only

- Secret fields (passwords, API tokens, secret keys) are never shown again
  after saving. The list shows **Credentials stored** instead.
- When you edit a configuration, leave a secret blank to keep the stored
  value; type a new value to replace it.
- If you change where credentials go (a URL or the appliance host), you must
  re-enter every stored secret in the same save. This stops a changed
  destination from receiving the old secrets.
- Webhook custom headers may not carry authentication (`Authorization`,
  `Cookie`, or names containing token, secret, key, auth, password and
  similar). Use the credential fields instead.

## Leave a setting for the targets

Some settings may be changed per target (for example the Cloudflare
`zone_id` or the BIG-IP `ssl_profile`). A *required* setting of this kind may
be left empty on a shared configuration: every target that uses the
configuration then supplies it. Such a configuration:

- cannot be deployed on its own: its **Deploy** button is disabled, with a
  hint naming the fields the target must supply;
- is deployed through a target, by [auto-deploy](auto-deploy.md) or by
  deploying to the target.

Settings that decide where credentials go (URLs, the appliance host) and the
TLS and header settings can never be changed by a target. The
[reference](../reference.md#target-overrides) lists what each provider
allows.

## Errors on save

A save that fails validation highlights the field and names it, for example
`config.region` or `credentials.api_token`. The value you typed is never
repeated in the error. Changing a configuration so that a target using it
would lose a required value is refused, and the error lists those targets.

## Delete a configuration

Open the configuration, choose **Delete** and confirm. The configuration is
also detached from every target that used it. Jobs that already ran stay in
the job list.
