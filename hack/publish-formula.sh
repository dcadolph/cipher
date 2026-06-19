#!/usr/bin/env bash
# Publish a Homebrew formula for cipher to the tap repo.
# Inputs:
#   TAG               Release tag (e.g. v0.1.1).
#   TAP_GITHUB_TOKEN  Fine-grained PAT with Contents:write on dcadolph/homebrew-tap.
# Reads dist/checksums.txt (produced by goreleaser) for per-asset sha256 values.

set -euo pipefail

: "${TAG:?TAG is required (e.g. v0.1.1)}"
: "${TAP_GITHUB_TOKEN:?TAP_GITHUB_TOKEN is required}"

VERSION="${TAG#v}"
CSUM="dist/checksums.txt"

if [[ ! -f "$CSUM" ]]; then
    echo "checksums file not found: $CSUM" >&2
    exit 1
fi

sha_for() {
    local pattern="$1"
    local sha
    sha=$(grep -E "[[:space:]]${pattern}\$" "$CSUM" | awk '{print $1}' | head -n1)
    if [[ -z "$sha" ]]; then
        echo "no sha256 found for $pattern in $CSUM" >&2
        exit 1
    fi
    printf '%s' "$sha"
}

SHA_DARWIN_ARM=$(sha_for "cipher_${VERSION}_Darwin_arm64.tar.gz")
SHA_DARWIN_AMD=$(sha_for "cipher_${VERSION}_Darwin_x86_64.tar.gz")
SHA_LINUX_ARM=$(sha_for "cipher_${VERSION}_Linux_arm64.tar.gz")
SHA_LINUX_AMD=$(sha_for "cipher_${VERSION}_Linux_x86_64.tar.gz")

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

git clone --depth 1 \
    "https://x-access-token:${TAP_GITHUB_TOKEN}@github.com/dcadolph/homebrew-tap.git" \
    "$WORK/tap"

cd "$WORK/tap"
mkdir -p Formula
if [[ -f Casks/cipher.rb ]]; then
    git rm -f Casks/cipher.rb
fi

cat > Formula/cipher.rb <<EOF
class Cipher < Formula
  desc "Programmatic SOPS for Go. Encrypt, decrypt, rotate, walk, edit, and audit secret files."
  homepage "https://github.com/dcadolph/cipher"
  version "${VERSION}"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/dcadolph/cipher/releases/download/${TAG}/cipher_${VERSION}_Darwin_arm64.tar.gz"
      sha256 "${SHA_DARWIN_ARM}"
    end
    on_intel do
      url "https://github.com/dcadolph/cipher/releases/download/${TAG}/cipher_${VERSION}_Darwin_x86_64.tar.gz"
      sha256 "${SHA_DARWIN_AMD}"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/dcadolph/cipher/releases/download/${TAG}/cipher_${VERSION}_Linux_arm64.tar.gz"
      sha256 "${SHA_LINUX_ARM}"
    end
    on_intel do
      url "https://github.com/dcadolph/cipher/releases/download/${TAG}/cipher_${VERSION}_Linux_x86_64.tar.gz"
      sha256 "${SHA_LINUX_AMD}"
    end
  end

  def install
    bin.install "cipher"
  end

  test do
    system "#{bin}/cipher", "version"
  end
end
EOF

git config user.name "cipher-release-bot"
git config user.email "cipher-release-bot@users.noreply.github.com"
git add Formula/cipher.rb

if git diff --cached --quiet; then
    echo "no changes to commit"
    exit 0
fi

git commit -m "cipher ${VERSION}"
git push origin HEAD:main
