# Releasing

This repository is a virtual workspace. Its packages share one version and
release tag. `release.yml` checks every workspace package's version against
the `v*` tag, runs workspace checks and a publish dry run, then publishes the
workspace using crates.io trusted publishing. A manual workflow run performs
checks and the dry run only.

## Publication inventory

The following workspace packages are intended for crates.io. None has been
published yet:

| Directory | Package |
| --- | --- |
| `core/` | `neotales-vaults-core` |
| `vaults/` | `neotales-vaults` |
| `os/` | `neotales-vaults-os` |
| `keepass/` | `neotales-vaults-keepass` |
| `age-json/` | `neotales-vaults-age-json` |
| `age-sqlite/` | `neotales-vaults-age-sqlite` |
| `vault/` | `neotales-vaults-vault` |
| `infisical/` | `neotales-vaults-infisical` |
| `vaultwarden/` | `neotales-vaults-vaultwarden` |
| `crypto/` | `neotales-vaults-crypto` |
| `azure/` | `neotales-vaults-azure` |
| `local-crypto/` | `neotales-vaults-local-crypto` |
| `aws/` | `neotales-vaults-aws` |
| `gcp/` | `neotales-vaults-gcp` |
| `local-json/` | `neotales-vaults-local-json` |

There are currently no workspace-only helper crates. If a test helper crate is
added, mark its manifest `publish = false`, exclude it from the publication
steps, and list it here separately. Integration tests and test-only dependencies
are not independently published packages. Update this inventory whenever a
workspace package is added or its publication intent changes.

## First release

The first version of each package is `0.0.0-alpha.0`. crates.io trusted
publishing cannot create a crate, so bootstrap each package manually using
`~/work/rs/publish.sh <package-directory>`. Publish `core/` first. Wait until
that version is visible in the registry before publishing its dependants.
`vaults/` must also be published before packages whose published tests depend
on it. Publish `local-crypto/` before `local-json/`, then publish the AWS,
Azure, and GCP crates after both local crates, whose tests they use. Wait for
each dependency to become visible before publishing its dependants. Do not
publish from an uncommitted worktree.

After each crate exists, configure its crates.io trusted publisher with
organization `neotales`, repository `rs-vaults`, workflow `release.yml`,
and an empty environment. Enable trusted-publishing-only mode after bootstrap.
Do not create the initial tag until the first uploads are complete.

## Later releases

1. Bump every package version and all sibling version requirements together.
2. Commit the manifests and `Cargo.lock`, then push to `dev`.
3. Run `cargo publish --workspace --dry-run --locked`.
4. Tag that commit with the matching `v` version and push the tag.

Cargo orders workspace uploads by their dependencies. A publish can partially
succeed before a later upload fails. Before retrying, inspect the registry and
the workflow log; do not assume the entire workspace failed or delete a tag.
An already uploaded version cannot be republished.

The workflow has no long-lived token and no GitHub environment. The crates.io
OIDC exchange must match the trusted publisher configured for each crate.
