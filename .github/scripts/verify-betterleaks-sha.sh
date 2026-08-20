#!/usr/bin/env bash
#
# Mitigation #7 from audits/betterleaks-v1.2.0.md.
#
# At release time, assert that go.sum's pinned betterleaks SHA still
# resolves to the SHA documented in THIRD_PARTY_AUDIT.md's review log.
# If they diverge, either:
#   - we accidentally bumped betterleaks without re-auditing (block
#     the release), or
#   - we deliberately bumped after a re-audit (in which case the
#     reviewer must update THIRD_PARTY_AUDIT.md's review-log SHA in
#     the same PR; the audit file is CODEOWNERS-gated to security).
#
# Either way, the release pipeline refuses to sign artifacts against a
# dep state that doesn't match the audited bytes.

set -euo pipefail

# Expected SHA, audited 2026-05-20 (per audits/betterleaks-v1.2.0.md).
EXPECTED_VERSION="v1.2.0"
EXPECTED_SHA="296fee33358904c47d094fa6716347b223b2c13f"

# Extract the actual version go.sum is pinning.
ACTUAL_VERSION="$(awk '$1=="github.com/betterleaks/betterleaks" {print $2; exit}' go.sum | sed 's|/go\.mod||')"
if [ -z "$ACTUAL_VERSION" ]; then
  echo "::error::could not find github.com/betterleaks/betterleaks in go.sum"
  exit 1
fi

if [ "$ACTUAL_VERSION" != "$EXPECTED_VERSION" ]; then
  cat >&2 <<EOF
::error::betterleaks version drift detected.

  Expected (audited): $EXPECTED_VERSION  (sha $EXPECTED_SHA)
  Actual (go.sum):    $ACTUAL_VERSION

Before this release can be signed:
  1. Re-audit the new version against THIRD_PARTY_AUDIT.md's review
     process. Write a fresh audits/betterleaks-<new-version>.md.
  2. Update this script's EXPECTED_VERSION and EXPECTED_SHA to match.
  3. Update THIRD_PARTY_AUDIT.md's review-log table.

The CODEOWNERS gate on THIRD_PARTY_AUDIT.md and on this script
ensures @webflow/infrastructure-security signs off on the bump.
EOF
  exit 1
fi

# Verify the on-disk source tree at the expected SHA by checking the
# module cache. go mod download/verify confirms checksums match go.sum;
# we additionally confirm the upstream tag still resolves to our
# expected commit (catches the "lightweight tag re-pointed upstream"
# class).
ACTUAL_SHA="$(git ls-remote https://github.com/betterleaks/betterleaks.git "refs/tags/${EXPECTED_VERSION}^{}" | awk '{print $1}')"
if [ -z "$ACTUAL_SHA" ]; then
  # Lightweight tag falls back to the tag's direct commit.
  ACTUAL_SHA="$(git ls-remote https://github.com/betterleaks/betterleaks.git "refs/tags/${EXPECTED_VERSION}" | awk '{print $1}')"
fi

if [ "$ACTUAL_SHA" != "$EXPECTED_SHA" ]; then
  cat >&2 <<EOF
::error::betterleaks $EXPECTED_VERSION tag now resolves to a different commit upstream.

  Expected: $EXPECTED_SHA
  Actual:   $ACTUAL_SHA

The upstream tag was re-pointed (betterleaks v1.2.0 is a lightweight
tag; the audit called this out as a structural risk). go.sum's
content hash MAY still match (in which case the actual go module
content is unchanged), but the tag pointer no longer matches the
audit reference. Investigate before signing this release.
EOF
  exit 1
fi

# Verify go.sum content integrity against the module cache.
go mod verify

echo "betterleaks integrity verified:"
echo "  version  $EXPECTED_VERSION"
echo "  sha      $EXPECTED_SHA"
echo "  go.sum   content-hash matches module cache"
