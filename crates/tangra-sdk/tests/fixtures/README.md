# Cross-check fixtures

Golden files produced by go-tangra **v4.10.0** (`helpdocs`, `catalogue`),
which the Rust tests compare against. Regenerate after changing a fixture:

```sh
# trees and descriptors
python3 tools/gen_helpdocs.py helpdocs        # valid/ and invalid/ trees (not deployer/)
python3 tools/gen_catalogue.py catalogue      # invalid-*.yaml from deployer.yaml
# goldens (Go 1.26, network or a `replace` to a local go-tangra checkout)
cd tools/gocheck && go mod tidy && go run . helpdocs ../../helpdocs && go run . catalogue ../../catalogue
```

- `helpdocs/valid/<name>/` loads in Go; `<name>.bundle.json` is Go's
  `Bundle.Marshal()` (compared byte for byte) and `<name>.digest` its
  `ComputeDigest`. Module `deployer` for `deployer/` (a copy of
  go-tangra-deployer-v4 `docs/help` at origin/main), `fixture` otherwise.
- `helpdocs/invalid/<name>/` is refused by Go; `<name>.problems.txt` holds
  Go's `Problems.Error()` for `Load` and `Lint` (compared line for line;
  only the wording of YAML syntax errors differs between yaml.v3 and
  yaml-rust2).
- `helpdocs/generated.golden`: trees too large to commit (501 pages, size
  limits, symlink, empty), rebuilt in memory by the Rust test.
- `helpdocs/frontmatter-cases.txt` / `frontmatter.golden`: 443 one-page trees
  probing yaml.v3 value resolution; Go's page JSON or problems for each.
- `catalogue/*.yaml`: the real `tangra-module.yaml` of deployer, paperless,
  warden, ipam, dns, ticket, scheduler, inventory and asset (origin/main)
  plus invalid variants; `<name>.golden` is `ok` + Go's JSON of the parsed
  descriptor, or `error: ` + Go's error text.
