# Releasing cipher

Releases are built and published by [GoReleaser](https://goreleaser.com/) on every `v*` tag pushed to `main`. The config lives at [`.goreleaser.yaml`](.goreleaser.yaml). The workflow lives at [`.github/workflows/release.yml`](.github/workflows/release.yml). A second step runs [`hack/publish-formula.sh`](hack/publish-formula.sh) to template and push a Homebrew formula to the tap repo.

## One-time setup

Done once by a maintainer. Skip every step that is already done.

### 1. Create the Homebrew tap repo

The release workflow publishes a formula to a separate tap repository on every release. The tap repo must exist before the first release.

1. Create a public repo named `homebrew-tap` under the same owner as `cipher` (so the URL is `https://github.com/dcadolph/homebrew-tap`).
2. Add a `Formula/` directory (an empty commit with `.gitkeep` is fine).
3. No further setup is required. `hack/publish-formula.sh` writes `Formula/cipher.rb` on each release.

### 2. Provision a tap-publishing token

The release workflow needs a token that can push to the tap repo. The default `GITHUB_TOKEN` only has access to the calling repo, so a personal access token is required.

1. Create a fine-grained personal access token at https://github.com/settings/tokens?type=beta.
2. Restrict it to the `dcadolph/homebrew-tap` repository.
3. Grant `Contents: read and write` and `Metadata: read-only`.
4. In the `cipher` repo, add the token as an Actions secret named `TAP_GITHUB_TOKEN` at https://github.com/dcadolph/cipher/settings/secrets/actions.

### 3. Verify locally (optional)

```sh
brew install goreleaser
goreleaser check
goreleaser release --snapshot --clean
```

`--snapshot` skips the publish step and writes binaries to `dist/`.

## Cutting a release

1. Make sure `main` is green on CI.
2. Pick a tag in `vMAJOR.MINOR.PATCH` form. Pre-1.0 uses `v0.MINOR.PATCH`.
3. Tag and push:

   ```sh
   git tag -s v0.1.0 -m "v0.1.0"
   git push origin v0.1.0
   ```

4. The release workflow runs. When it finishes:
   - A GitHub release with binaries and `checksums.txt` is published at https://github.com/dcadolph/cipher/releases/tag/v0.1.0.
   - A commit lands on `dcadolph/homebrew-tap` updating `Formula/cipher.rb`.
   - End users can immediately run `brew install dcadolph/tap/cipher`.

## What gets built

| Target | Artifacts |
|--------|-----------|
| Linux amd64 and arm64 | `cipher_VERSION_Linux_x86_64.tar.gz`, `cipher_VERSION_Linux_arm64.tar.gz`. |
| macOS amd64 and arm64 | `cipher_VERSION_Darwin_x86_64.tar.gz`, `cipher_VERSION_Darwin_arm64.tar.gz`. |
| Windows amd64 and arm64 | `cipher_VERSION_Windows_x86_64.zip`, `cipher_VERSION_Windows_arm64.zip`. |
| Checksums | `checksums.txt` with SHA-256 for every artifact. |
| Homebrew formula | Pushed to `dcadolph/homebrew-tap` under `Formula/cipher.rb`. Points at the release archive URLs and their SHA-256 sums. End users install with `brew install dcadolph/tap/cipher` (no `brew trust` prompt since formulae are auto-trusted). |

Each archive bundles `README.md`, `LICENSE`, and `SECURITY.md` alongside the binary.

## Yanking a bad release

1. Delete the GitHub release at https://github.com/dcadolph/cipher/releases.
2. Delete the tag locally and on the remote:

   ```sh
   git tag -d v0.1.0
   git push --delete origin v0.1.0
   ```

3. Revert the formula commit on `dcadolph/homebrew-tap`.

Yanking should be rare. Prefer cutting a fix release with a bumped patch.
