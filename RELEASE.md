# Releasing decayfmt

Binaries, the GitHub Release, and the crates.io publish are all automated. A release
is a version bump and one tag.

## What a `v*` tag does

Pushing a `v*` tag starts `release.yml`, which builds and tests on five targets (Linux
x86_64 + aarch64, macOS x86_64 + arm64, Windows msvc), attaches the archives to the
GitHub Release, and publishes the crate to crates.io.

The publish waits for the whole build matrix to pass, because a crates.io version can
never be reused once uploaded. If it fails after some archives are attached, recover by
fixing the cause and releasing a new patch version rather than retrying the same one.

## Releasing a new version

1. Bump `version` in `Cargo.toml` and let `cargo check` carry it into `Cargo.lock`.
2. Tag and push:

   ```bash
   git tag v0.3.0
   git push origin v0.3.0
   ```

3. Verify:

   ```bash
   cargo install decayfmt --force && decayfmt --version
   ```

## Dependencies

Dependabot opens a pull request each month when crates or actions update, grouped so a
month of routine drift is one review. CI runs against every one, so merging a green pull
request is the whole process. Major bumps come as their own pull request; `rand` is
excluded from those because the corruption invariant depends on it.

Before cutting a release, run `cargo update` and commit the lockfile with the release.
That catches drift at the one moment everything is being tested anyway.

## Publishing setup

crates.io uses trusted publishing: a GitHub OIDC token is exchanged for a short-lived
registry token, so no API tokens are stored in the repository. This is configured
already and is recorded here so it can be rebuilt if it is ever lost.

**crates.io** (crate → Settings → Trusted Publishing):

| Field | Value |
| --- | --- |
| Repository owner | `aravpanwar` |
| Repository name | `decayfmt` |
| Workflow filename | `release.yml` |
| Environment name | empty |

A crate must already exist on crates.io before a trusted publisher can be
attached to it, so the very first version of a new crate is published manually.
