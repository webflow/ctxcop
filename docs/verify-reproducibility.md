# Verify a release was built from source

ctxcop's release binaries are bit-for-bit reproducible. Given the
source at the tag, the Go toolchain version pinned in `go.mod`, and
the build flags below, anyone can rebuild a tagged release and
confirm the sha256 matches the one published on the GitHub Release.

That removes "trust our CI in isolation" as a requirement — if the
sha256 matches, the published binary was built from public source
without tampering.

## Quick check (paste-and-run)

Replace `v0.1.0`, `darwin`, `arm64` with the tag and target you care
about. Needs `git`, `go`, the GitHub CLI (`gh`, authenticated via
`gh auth login`), and either `sha256sum` (Linux) or `shasum` (macOS).

```sh
TAG=v0.1.0
GOOS=darwin
GOARCH=arm64

# 1. Clone at the tag.
git clone --depth=1 --branch "$TAG" https://github.com/webflow/ctxcop /tmp/ctxcop-verify
cd /tmp/ctxcop-verify

# 2. Derive the inputs the release pipeline used.
COMMIT="$(git rev-parse HEAD)"
SOURCE_DATE_EPOCH="$(git log -1 --pretty=%ct "$COMMIT")"
BIN="ctxcop_${TAG}_${GOOS}_${GOARCH}"

# 3. Rebuild with the exact flags from .github/workflows/release.yml.
GOOS="$GOOS" GOARCH="$GOARCH" CGO_ENABLED=0 GOFLAGS=-mod=readonly \
  go build \
    -trimpath \
    -ldflags "-s -w -X main.version=${TAG} -X main.commit=${COMMIT} -X main.date=${SOURCE_DATE_EPOCH}" \
    -o "$BIN" \
    ./cmd/ctxcop

# 4. Fetch the published sha256 and compare. `gh release download`
#    works against both public and private/internal repos; raw curl
#    only works post-public-flip.
gh release download "$TAG" --repo webflow/ctxcop --pattern "${BIN}.sha256" --clobber

LOCAL="$( (command -v sha256sum >/dev/null && sha256sum "$BIN" || shasum -a 256 "$BIN") | awk '{print $1}')"
UPSTREAM="$(awk '{print $1}' "${BIN}.sha256")"

if [ "$LOCAL" = "$UPSTREAM" ]; then
  echo "MATCH: local rebuild sha256 == published sha256 ($LOCAL)"
else
  echo "MISMATCH:"
  echo "  local:    $LOCAL"
  echo "  upstream: $UPSTREAM"
  exit 1
fi
```

If the final line reads `MATCH:`, the binary on the release page is a
deterministic rebuild of the tag's source tree.

**Without `gh`:** once `webflow/ctxcop` is public, the sha256 file is
directly fetchable. Substitute step 4 with:

```sh
curl -fsSL -o "${BIN}.sha256" \
  "https://github.com/webflow/ctxcop/releases/download/${TAG}/${BIN}.sha256"
```

For private/internal builds, `curl` will 404; stick with `gh`.

## Why these specific flags

| Flag / env | Why |
| --- | --- |
| `CGO_ENABLED=0` | Pure Go output — no link against host libc, identical across distros. |
| `-trimpath` | Strips the build-time absolute paths from the binary's debug info. Without it, every rebuild encodes the build host's `/Users/.../` or `/home/.../`. |
| `GOFLAGS=-mod=readonly` | Refuse to touch `go.sum`; fail if the lockfile and module cache diverge. |
| `-ldflags -s -w` | Drop the symbol/debug tables. Smaller binary, also strips a few bytes that would otherwise differ between Go releases. |
| `-X main.version` / `main.commit` / `main.date` | Linker-injected build metadata. `main.date` uses `SOURCE_DATE_EPOCH` so two rebuilds at different wall-clock times produce identical bytes. |
| `SOURCE_DATE_EPOCH` from the tag's commit timestamp | The canonical timestamp every reproducible-builds tool keys on. ctxcop's pipeline uses `git log -1 --pretty=%ct $COMMIT`. |
| `go-version-file: go.mod` in CI | The pipeline pins Go to the `go` directive in `go.mod` at the tag. Reproducers must match — newer Go can change codegen subtly and break bit-equality. |

## Toolchain pinning

ctxcop tracks Go's minor releases on a deliberate cadence — every
release tag pins a specific `go` directive in `go.mod`. To verify
reproducibility you need that *exact* Go toolchain, not just "Go 1.26
or later".

Find the version a tag was built with:

```sh
git -C /tmp/ctxcop-verify show "$TAG:go.mod" | grep '^go '
```

Match it with whatever Go toolchain manager you use (`gimme`, `mise`,
`asdf`, the official downloads at https://go.dev/dl/, etc.). The
pipeline uses GitHub's `actions/setup-go` with `go-version-file:
go.mod`, which resolves to the toolchain release that file pins.

## What this does NOT verify

Reproducibility says "the binary on the release page is a faithful
build of the tag's source." It does not say:

- The source itself is benign. Read the diff between tags if you
  care about content review.
- The release was signed by an allowlisted identity. That's what
  cosign verification handles — see [SECURITY.md](../SECURITY.md) for
  the `cosign verify-blob` command.
- The dependencies haven't been compromised. CI runs `govulncheck`
  (reachability-aware) and `osv-scanner` on every PR and daily against
  `main`, and `go.sum` pins every dependency by content hash — including
  `betterleaks`, whose reviewed SHA is recorded in
  [THIRD_PARTY_AUDIT.md](../THIRD_PARTY_AUDIT.md). Those catch *known*
  advisories and unauthorized content changes; neither proves a
  dependency is benign. Independent verification of dep integrity
  belongs in a separate workflow.

Run both checks — reproducibility *and* cosign — for the strongest
claim. They protect against different attacks:

| Threat | Reproducibility catches | cosign catches |
| --- | --- | --- |
| CI compromised, binary built from different source | ✓ | ✗ |
| Source tree tampered, then signed by a legitimate identity | ✗ (source matches built artifact) | ✗ |
| Binary swapped on the release page after publish | ✓ | ✓ |
| Release identity not the documented workflow path | ✗ | ✓ |
| Replay of an old signature against a new binary | ✗ | ✓ (Rekor transparency log) |

## Reporting a mismatch

If the local rebuild sha256 doesn't match the published sha256 and
you've ruled out a Go-toolchain mismatch, treat it as a potential
supply-chain incident and open a private security advisory at
https://github.com/webflow/ctxcop/security/advisories. Include the
tag, your Go version, your OS/arch, and both sha256 values. See
[SECURITY.md](../SECURITY.md) for the disclosure protocol.
