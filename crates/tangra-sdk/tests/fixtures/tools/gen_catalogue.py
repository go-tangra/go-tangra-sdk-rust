#!/usr/bin/env python3
"""Writes the invalid catalogue descriptors (invalid-*.yaml, plus
optional-input.yaml and too-many-inputs) under argv[1], derived from the
real deployer descriptor (deployer.yaml, copied from go-tangra-deployer-v4
origin/main like the other real descriptors)."""
import os
import sys

d = sys.argv[1]
base = open(os.path.join(d, "deployer.yaml")).read()


def w(name, s):
    open(os.path.join(d, name + ".yaml"), "w").write(s)


def rep(name, a, b):
    assert a in base, a
    w("invalid-" + name, base.replace(a, b, 1))


rep("schema", "schema: 1", "schema: 2")
rep("unknown-field", "schema: 1", "schema: 1\nauthor: me")
rep("unknown-nested", "  names: [deployer]", "  names: [deployer]\n  extra: 1")
rep("module", "module: deployer", "module: Deployer")
rep("display-empty", "display_name: Deployer", "display_name: ''")
rep("display-long", "display_name: Deployer", "display_name: " + "D" * 61)
rep("category-long", "category: Certificates", "category: " + "c" * 41)
rep("summary-long", "summary: Deploys", "summary: " + "s" * 200 + " Deploys")
rep("image-tag", "image: ghcr.io/go-tangra/go-tangra-deployer", "image: ghcr.io/go-tangra/go-tangra-deployer:1.0")
rep("prefix-scope", "prefixes: [/api/deployer, /m/deployer, /deployer]", "prefixes: [/api/other]")
rep("prefix-unclean", "prefixes: [/api/deployer, /m/deployer, /deployer]", "prefixes: [/api/deployer/]")
rep("prefix-none", "prefixes: [/api/deployer, /m/deployer, /deployer]", "prefixes: []")
rep("names", "names: [deployer]", "names: [deployer, x]")
rep("min-core-component", "min_core: { gateway: 4.9.0, auth: 4.10.0 }", "min_core: { portal: 4.9.0 }")
rep("min-core-version", "min_core: { gateway: 4.9.0, auth: 4.10.0 }", "min_core: { gateway: v4.9.0 }")
rep("reserved-key", "key: VALKEY_CA_FILE", "key: GEN_SECRET")
rep("reserved-core", "key: VALKEY_CA_FILE", "key: TRUST_DOMAIN")
rep("module-image", "key: VALKEY_CA_FILE", "key: MODULE_IMAGE")
rep("dup-key", "key: VALKEY_CA_FILE", "key: VALKEY_PASSWORD")
rep("bad-key", "key: VALKEY_CA_FILE", "key: valkey_ca")
rep("label-empty", "label: Host file of the CA certificate (PEM) of the core event bus (mounted read-only)", "label: ''")
rep("unanchored", "pattern: '^/[A-Za-z0-9._/-]{0,254}$'", "pattern: '/[a-z]+'")
rep("bad-pattern", "pattern: '^/[A-Za-z0-9._/-]{0,254}$'", "pattern: '^([a-z]$'")
rep("default-mismatch", "pattern: '^/[A-Za-z0-9._/-]{0,254}$'", "pattern: '^/[a-z]+$'\n    default: nope")
rep("docs-http", "docs: https://github.com", "docs: http://github.com")
rep("bundle-dir", "dir: deploy/bundle", "dir: ../bundle")
rep("bundle-dir-abs", "dir: deploy/bundle", "dir: /srv/bundle")
rep("templates-none", "templates: [config.yaml, policy.yaml]", "templates: []")
rep("template-escape", "templates: [config.yaml, policy.yaml]", "templates: [config.yaml, '../x']")
rep("template-backslash", "templates: [config.yaml, policy.yaml]", "templates: ['a\\\\b']")
rep("tls-host", "tls_hosts: [deployer-db]", "tls_hosts: [Deployer_DB]")
rep("schema-string", "schema: 1", "schema: 'one'")
rep("dup-field", "category: Certificates", "category: Certificates\ncategory: Other")
w("optional-input", base.replace("pattern: '^/[A-Za-z0-9._/-]{0,254}$'",
                                 "pattern: '^/[A-Za-z0-9._/-]{0,254}$'\n    optional: true\n    default: /etc/ca.pem", 1))
w("invalid-empty", "")
w("invalid-not-mapping", "- a\n- b\n")
w("invalid-too-many-inputs", base.split("host_inputs:")[0] + "host_inputs:\n" +
  "".join(f"  - {{key: K{i:02d}X, label: L, pattern: '^a$'}}\n" for i in range(21)))
warden = open(os.path.join(d, "warden.yaml")).read()
w("invalid-multi-errors", warden.replace("schema: 1", "schema: [1]\nfoo: 1\nschema: 2").replace(
    "    default: warden", "    default: {a: 1}\n    optional: maybe\n    extra: x"))
w("scalars", warden.replace("category: Security", "category: 12.5").replace(
    "    default: warden", "    default: 0x1f\n    optional: yes"))
w("invalid-type-errors", warden.replace("schema: 1", "schema: [1]\nfoo: 1").replace(
    "    default: warden", "    default: {a: 1}\n    optional: maybe\n    extra: x").replace(
    "  names: [warden]", "  names: [warden, [x], ~]\n  other: 1").replace(
    "min_core: { gateway: 4.9.0, auth: 4.10.0 }", "min_core: { gateway: [4], auth: ~ }").replace(
    "tls_hosts: [warden-db, warden-valkey]", "tls_hosts: warden-db"))
