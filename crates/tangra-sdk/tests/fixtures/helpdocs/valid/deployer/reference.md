---
title: Reference
summary: Job, target and configuration fields, job states and triggers, filter fields, target overrides per provider, permissions, roles, API routes and limits.
kind: reference
order: 60
tags: [deployer, reference, jobs, states, permissions, api, limits]
---
## Job fields

| Field | Meaning |
|---|---|
| `id` | job ID |
| `type` | `direct`, `parent` or `child` |
| `certificate_id` | the lcm certificate deployed |
| `certificate_serial` | its serial number |
| `deployment_target_id` | the target (parent jobs) |
| `target_configuration_id` | the configuration (direct and child jobs) |
| `parent_job_id` | the parent (child jobs) |
| `status` | see [job states](#job-states) |
| `status_message` | the latest progress note or outcome |
| `error` | cause of the last failure, credentials removed; cleared by a success |
| `progress` | 0–100; for a parent, the share of finished children |
| `retry_count` / `max_retries` | automatic retries used / allowed (3) |
| `triggered_by` | see [triggers](#triggers) |
| `created_at`, `completed_at` | timestamps |

## Job states

| State | Meaning | Final |
|---|---|:-:|
| `pending` | waiting for a worker | |
| `processing` | running | |
| `retrying` | failed, another attempt is scheduled | |
| `completed` | deployed (parent: all children completed) | yes |
| `partial` | parent only: some children failed | yes |
| `failed` | failed and no retries left, or a failure retrying cannot fix | yes |
| `cancelled` | cancelled by a user, or its parent was cancelled | yes |

`failed` and `partial` jobs can be retried; see [jobs](guides/jobs.md#actions).

## Triggers

| `triggered_by` | Set when |
|---|---|
| `manual` | a user or a service deployed by hand |
| `event` | auto-deploy on `certificate.issued` |
| `auto_renewal` | auto-deploy on `certificate.renewed` |

## History entries

Each attempt adds an entry with `action` (`deploy`, `verify`, `rollback`),
`result` (`success`, `failure`, `partial`), a `message` and `duration_ms`.

## Configuration fields

| Field | Meaning |
|---|---|
| `name` | 1–100 characters, unique in the tenant |
| `provider_type` | `aws_acm`, `bigip`, `cloudflare`, `dummy`, `fortigate`, `inventory-agent`, `webhook`; fixed after creation |
| `config` | provider settings |
| `has_credentials` | credentials are stored (their values are never returned) |
| `target_supplied` | required settings left for targets to supply |
| `status` | `active`, `inactive` or `error`; only an `active` configuration can be deployed |
| `last_deployment_at` | time of the last successful deployment |

## Target fields

| Field | Meaning |
|---|---|
| `name` | 1–100 characters |
| `auto_deploy` | deploy on matching issue and renewal events |
| `certificate_filters` | list of filters, OR between filters, AND within one |
| `configuration_ids` | attached configurations |
| `config_overrides` | per configuration ID, the settings the target supplies or changes |
| `missing_required` | per configuration, required settings still missing |

### Certificate filter fields

| Field | Compared with | Match |
|---|---|---|
| `issuer_name` | issuer name | exact |
| `common_name_pattern` | subject CN | pattern |
| `san_pattern` | each SAN | pattern |
| `subject_organization` | subject O | exact |
| `subject_org_unit` | subject OU | exact |
| `subject_country` | subject C | exact |

Patterns: `*.domain` matches one label in front of the domain; anything
else is an RE2 expression matched against the whole value. Unknown fields
are refused (`400 malformed_body`).

## Target overrides

A target may supply or change only these settings. Credentials, URLs, the
appliance host and TLS and header settings are never overridable.

| Provider | Overridable settings |
|---|---|
| AWS Certificate Manager | `region`, `certificate_arn` |
| F5 BIG-IP | `partition`, `ssl_profile` |
| Cloudflare | `zone_id` |
| Dummy | `fail` |
| FortiGate | `vdom`, `import_scope`, `profile_suffix`, `default_ssl_profile` |
| Inventory agent | `host_ids`, `host_tags`, `cert_name`, `key_policy`, `require_all_success`, `wait_seconds` |
| Webhook | `timeout_seconds`, `metadata` |

FortiGate `replace_strategy`, `rebind_references` and `prune_old` decide what
the provider deletes, so a target cannot change them. The live list of every
provider field is `GET /api/deployer/v1/providers`.

## Permissions and roles

| Permission | Allows |
|---|---|
| `configurations:read` | list and read configurations (credentials redacted), list providers |
| `configurations:manage` | create, change, delete and test configurations |
| `targets:read` | list and read targets and their filters |
| `targets:manage` | create, change and delete targets and attachments |
| `jobs:read` | list and read jobs and their history; receive live job events |
| `jobs:manage` | cancel and retry jobs |
| `deploy:execute` | deploy, verify and roll back |
| `stats:read` | read the dashboard statistics |
| `backup:manage` | export and import the tenant's deployer setup |

| Module role | Permissions |
|---|---|
| Deployer administrator | all nine |
| Deployer operator | `configurations:read`, `targets:read`, `jobs:read`, `jobs:manage`, `deploy:execute` |
| Deployer viewer | `configurations:read`, `targets:read`, `jobs:read`, `stats:read` |

The platform's built-in roles also receive deployer permissions: `owner` and
`admin` all; `operator` all but `backup:manage`; `auditor` `stats:read` and
`jobs:read`; `member` `configurations:read`, `targets:read` and
`stats:read` (members do not see jobs).

## API

The browser API is under `/api/deployer/v1`, through the gateway. Changing
requests need the `X-CSRF-Token` header.

| Route | Permission |
|---|---|
| `GET /providers` | `configurations:read` |
| `GET /configurations`, `GET /configurations/{id}` | `configurations:read` |
| `POST /configurations`, `PUT /configurations/{id}`, `POST /configurations/{id}/remove`, `POST /configurations/validate` | `configurations:manage` |
| `GET /targets`, `GET /targets/{id}`, `GET /targets/{id}/configurations` | `targets:read` |
| `POST /targets`, `PUT /targets/{id}`, `POST /targets/{id}/remove`, `POST /targets/{id}/configurations`, `POST /targets/{id}/configurations/remove` | `targets:manage` |
| `POST /deploy` (one configuration), `POST /deploy/target`, `POST /deploy/configurations` | `deploy:execute` |
| `POST /deploy/{job_id}/verify`, `POST /deploy/{job_id}/rollback` | `deploy:execute` |
| `GET /jobs`, `GET /jobs/{id}`, `GET /jobs/{id}/children`, `GET /jobs/{id}/history`, `GET /jobs/{id}/result` | `jobs:read` |
| `POST /jobs/{id}/cancel`, `POST /jobs/{id}/retry` | `jobs:manage` |
| `GET /statistics`, `GET /statistics/tenant` | `stats:read` |
| `POST /backup/export`, `POST /backup/import` | `backup:manage` |

Deploy requests answer `202` with the job ID; the outcome arrives as live
events and on the job.

### Errors

| Status | `reason` | Typical cause |
|---|---|---|
| 400 | `malformed_body` | invalid JSON or an unknown field |
| 403 | `forbidden` | the permission is missing |
| 404 | `not_found` | no such item in your tenant |
| 409 | `unsupported` | verify or rollback on a parent job or a provider without it |
| 422 | `validation_failed` | a field is invalid (`detail.fields` names it), the configuration is not active, or the target has no configurations |
| 422 | `credentials_rejected` | the endpoint refused the credentials during a test |

## Limits

| Limit | Value |
|---|---|
| name of a configuration or target | 100 characters |
| filter pattern | 256 characters (longer never matches) |
| list page size | 200 |
| JSON request body | 64 KiB |
| automatic retries per job | 3 |
| job attempt timeout | `jobs.job_timeout_seconds` (default 300 s) |
| job retention | `jobs.cleanup_days` (default 30 days) |
