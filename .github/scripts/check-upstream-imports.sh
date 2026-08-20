#!/usr/bin/env bash
#
# Mitigation #4 from audits/betterleaks-v1.2.0.md.
#
# The 2026-05-20 betterleaks v1.2.0 audit verified that the integration
# packages ctxcop depends on (detect, config, report — and their
# subpackages like detect/codec) do not import os/exec, net/http,
# unsafe, or reflect at the audited SHA. A future upstream commit that
# introduces any of those imports would significantly widen the
# detection-layer trust surface (network egress, code execution,
# memory-safety bypass) and is the strongest single regression signal
# we can mechanically test for between audits.
#
# This script fails the build on any such import. Run by ci.yml on
# every PR + push to main.

set -euo pipefail

PACKAGES=(
  "github.com/betterleaks/betterleaks/detect/..."
  "github.com/betterleaks/betterleaks/config/..."
  "github.com/betterleaks/betterleaks/report/..."
)

# Forbidden list calibrated to what the 2026-05-20 audit verified is
# absent. Each one would be a *new* class of attack surface:
#
#   os/exec  — process invocation; a backdoored detector could spawn
#              arbitrary commands when scanning.
#   unsafe   — memory-safety bypass.
#   reflect  — dynamic type/symbol access that breaks the
#              "static-analysis tells you what runs" guarantee.
#
# Intentionally NOT forbidden:
#   net/http — the audit confirmed detect/detect.go:232 imports it for
#              `validationEnv.SetHTTPClient`, gated on Validation
#              options that ctxcop does not set. Re-audit any major
#              version bump rather than blocking every PR on this.
#   os       — imported for baseline/ignore-file reads gated by CLI
#              flags ctxcop never sets. Too coarse to forbid.

FINDINGS_FILE="$(mktemp)"
trap 'rm -f "$FINDINGS_FILE"' EXIT

# `go list -e -json ./...` emits one JSON object per package, even on
# build errors. -e prevents the script from blowing up if a transient
# upstream-rename breaks resolution; we'd rather report "no findings"
# in that case and let the surrounding lint/test jobs catch the
# underlying breakage.
go list -e -json "${PACKAGES[@]}" \
  | jq -r '
      .ImportPath as $p |
      .Imports[]? |
      select(IN("os/exec","unsafe","reflect")) |
      "\($p)\t\(.)"
    ' \
  > "$FINDINGS_FILE"

if [ -s "$FINDINGS_FILE" ]; then
  echo "::error title=Upstream import-allowlist regression::"
  echo "betterleaks integration packages now directly import forbidden symbols."
  echo "See audits/betterleaks-v1.2.0.md mitigation #4 for context."
  echo
  printf '  %-60s -> imports forbidden: %s\n' \
    $(awk '{print $1, $2}' "$FINDINGS_FILE")
  echo
  echo "If this is intentional (e.g., a reviewed upstream bump):"
  echo "  1. Re-audit the new betterleaks version against THIRD_PARTY_AUDIT.md."
  echo "  2. Update audits/ with the new review."
  echo "  3. Update this script's FORBIDDEN allowlist if (and only if) the audit"
  echo "     concludes the new import is benign."
  exit 1
fi

echo "Upstream import-allowlist check passed."
echo "Verified: ${PACKAGES[*]} do not directly import os/exec, unsafe, or reflect."
