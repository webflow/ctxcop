#!/usr/bin/env bash
#
# Verifies the git tag that triggered the release workflow:
#   1. Tag must be an annotated tag (not lightweight).
#   2. Tag must be cryptographically signed.
#   3. Signer's pubkey must be in .github/release-allowed-signers.
#
# Fails the build (exit 1) if any of those isn't true. Run as the
# first job of release.yml; downstream build/sign/publish jobs depend
# on this passing.
#
# The allowed-signers file is the chokepoint of the release-signing
# pipeline. Even if a malicious maintainer adds themselves to the
# repo's admin role, they need a signing key in this file (added via
# a CODEOWNERS-gated PR) to mint a tag the workflow accepts.

set -euo pipefail

tag="${GITHUB_REF#refs/tags/}"
if [ -z "$tag" ] || [ "$tag" = "${GITHUB_REF}" ]; then
  echo "::error::release workflow triggered without a tag ref (GITHUB_REF=$GITHUB_REF)"
  exit 1
fi

# 1. Annotated, not lightweight.
type="$(git cat-file -t "$tag")"
if [ "$type" != "tag" ]; then
  cat >&2 <<EOF
::error::tag '$tag' is a lightweight tag, not an annotated one.

Release tags must be annotated AND signed:
  git tag -s -a $tag -m "release $tag"

A lightweight tag is just a moveable pointer with no signature
metadata, which means the release pipeline can't verify who cut
the tag. Cut a new annotated+signed tag and push it.
EOF
  exit 1
fi

# 2 + 3. Signed by an allowed signer.
signers_file=".github/release-allowed-signers"
if [ ! -f "$signers_file" ]; then
  echo "::error::missing $signers_file — required to verify release-tag signatures"
  exit 1
fi
# Reject the template-only state (no real keys yet).
if ! grep -qE '^[^#[:space:]]' "$signers_file"; then
  cat >&2 <<EOF
::error::$signers_file contains no active signing keys (only comments).

Populate it with at least one pubkey before cutting a release. See the
file header for the expected format.
EOF
  exit 1
fi

# git tag -v reads the allowedSignersFile from git config; point it
# at our repo-checked-in file for this run.
mkdir -p "$HOME/.config/git"
cp "$signers_file" "$HOME/.config/git/allowed_signers"
git config --global gpg.format ssh
git config --global gpg.ssh.allowedSignersFile "$HOME/.config/git/allowed_signers"

if ! git tag -v "$tag" 2>&1 | tee /tmp/tag-verify.log; then
  cat >&2 <<EOF
::error::tag '$tag' did not verify against $signers_file.

If you cut this tag with a key that isn't in the allowed-signers list,
either (a) add the key via a CODEOWNERS-gated PR and recut, or (b)
recut the tag using an already-allowed key.
EOF
  exit 1
fi

echo "Tag verified: '$tag' is annotated, signed, and signer is in $signers_file."
