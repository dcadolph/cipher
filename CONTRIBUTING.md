# Contributing to cipher

Patches welcome. This document covers how to get set up, what the CI runs, and what to expect during review.

## Development environment

- Go 1.25 or newer.
- A working `gpg` binary if you plan to touch the PGP backend.
- [`golangci-lint`](https://golangci-lint.run/) for the lint workflow.
- [`goreleaser`](https://goreleaser.com/) if you plan to touch release configuration.

## Setup

```sh
git clone https://github.com/dcadolph/cipher
cd cipher
make build
make test
make lint
```

Run `make help` for every available target.

## What CI runs

| Workflow | Trigger | What it does |
|----------|---------|--------------|
| [test](.github/workflows/test.yml) | push to `main`, pull request | `go test ./...` on Linux and macOS with Go 1.25.x. Coverage uploaded to [Codecov](https://codecov.io/gh/dcadolph/cipher). |
| [lint](.github/workflows/lint.yml) | push to `main`, pull request | `golangci-lint run`. |
| [integration](.github/workflows/integration.yml) | push to `main`, pull request | Starts a dev vault container, runs the `integration` tag tests against it. |
| [bench](.github/workflows/bench.yml) | manual dispatch, push to `main` that touches Go files | Runs the benchmark suite and posts the output. |
| [release](.github/workflows/release.yml) | tag push matching `v*` | GoReleaser builds binaries, publishes the GitHub release, pushes the Homebrew cask. See [RELEASING.md](RELEASING.md). |

Run the same checks locally before opening a pull request to avoid round trips. Integration tests need a running vault and the `integration` build tag, e.g. `VAULT_ADDR=http://localhost:8200 VAULT_TOKEN=root go test -tags integration ./vault/`.

## Codecov setup (one time)

The test workflow uploads `coverage.out` to Codecov on every Linux run. The action falls back to tokenless upload for public repos, but a token is recommended for reliability:

1. Sign in to [codecov.io](https://codecov.io) with the GitHub account that owns the repo.
2. Add the repo and copy its upload token.
3. Save the token as the `CODECOV_TOKEN` secret on the cipher repo at https://github.com/dcadolph/cipher/settings/secrets/actions.

The workflow has `fail_ci_if_error: false`, so a Codecov outage does not block CI.

## Commit and PR style

- Imperative, short subjects under 72 characters. `Add walk progress reporting.` not `Added walk progress reporting and fixed the bug.`
- Body explains the why, not the what, unless the change is obvious from the diff.
- One logical change per commit. Squash review fixups before merge.
- PR titles follow the same convention as commit subjects.
- PR descriptions cover summary, test plan, and any visible behavior change worth a screenshot.

## Tests

- Table-driven. See existing `*_test.go` files for the project's house style.
- `t.Parallel()` at the top of every test that does not share global state.
- Use [`github.com/google/go-cmp/cmp`](https://pkg.go.dev/github.com/google/go-cmp/cmp) for diffing. The project does not use testify.
- Fixtures go under `testdata/` per package.

## Backends

Backend tests that need cloud credentials are skipped without them. Set the relevant environment variable (`AWS_PROFILE`, `GOOGLE_APPLICATION_CREDENTIALS`, `VAULT_TOKEN` plus `VAULT_ADDR`, Azure CLI, gpg keyring) to opt in.

## Reporting bugs

Open a GitHub issue using the bug template. For security reports use [GitHub Security Advisories](https://github.com/dcadolph/cipher/security/advisories/new) per [SECURITY.md](SECURITY.md). Do not open public issues for vulnerabilities.

## Proposing features

Open an issue using the feature template before writing code for non-trivial changes. Aligning on shape early saves rework.

## License

Patches are submitted under the same Apache-2.0 license as the rest of the project. By opening a pull request you agree to license your contribution under those terms.
