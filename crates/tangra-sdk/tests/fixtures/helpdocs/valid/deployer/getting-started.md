---
title: Get started
summary: Create a test configuration with the Dummy provider and deploy a certificate to it.
kind: guide
order: 10
tags: [deployer, getting-started, dummy]
requires: configurations:manage
---
This walk-through deploys a certificate to the **Dummy** provider, which
installs nothing and always succeeds. It shows the whole flow without touching
real infrastructure.

You need the `configurations:manage` and `deploy:execute` permissions (the
*Deployer administrator* role has both), and `jobs:read` to watch the job.

## 1. Create a configuration

1. Open **Deployer → Configurations** and choose **New configuration**.
2. Give it a name, for example `test-dummy`.
3. In **Provider**, choose **Dummy (testing)**.
4. Leave **Fail** off and choose **Check settings**. The drawer answers
   "The settings are valid."
5. Choose **Save**. The configuration appears in the list with status
   `active`.

## 2. Find a certificate

The deployer deploys certificates that lcm issued. Open **Certificates**,
pick a certificate (or issue one) and copy its ID.

## 3. Deploy

1. Back in **Deployer → Configurations**, choose **Deploy** on the
   `test-dummy` row.
2. Paste the certificate ID into **Certificate ID** and confirm.
3. A message confirms that the deployment started and shows the job ID.

## 4. Watch the job

Open **Deployer → Jobs**. The new job is a *direct* job triggered `manual`.
It moves from `pending` through `processing` to `completed` without a page
refresh. Open it to see its **History**: one `deploy` entry with result
`success` and its duration.

## Next steps

- Set up a real provider: [manage configurations](guides/configurations.md).
- Let renewals deploy themselves: [auto-deploy](guides/auto-deploy.md).
- If the job fails, see [jobs](guides/jobs.md).
