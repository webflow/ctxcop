# Third-party dependency audit log

This file tracks ctxcop's posture on each non-stdlib runtime dependency,
with explicit attention to single-maintainer or otherwise risk-carrying
upstreams. It complements `NOTICES.md` (which documents license and
attribution) and `SECURITY.md` (which documents how we respond when a
dep is compromised).

For every direct dependency, this file records:

- Current pinned version.
- Maintainer status (single, small team, large org).
- Why we use it and what would replace it if we had to.
- Review log: who reviewed which version, when, and what they checked.

## Update policy

- **Dependabot** opens PRs for `gomod` updates weekly (see
  `.github/dependabot.yml`). Most direct/indirect updates auto-merge if
  CI is green and the diff stays within minor/patch.
- **`github.com/betterleaks/betterleaks` is explicitly excluded from
  Dependabot.** Every bump is manual and lands here with an audit entry
  before merging.
- **No fast-following.** A new betterleaks release waits at least 7 days
  before we evaluate it, so the security community has time to find
  issues. Exceptions: an advisory specifically affecting our usage.

## betterleaks (`github.com/betterleaks/betterleaks`)

| Field | Value |
|---|---|
| Current pin | `v1.2.0` |
| Upstream | https://github.com/betterleaks/betterleaks |
| Maintainer | Zachary Rice (single maintainer; original gitleaks author) |
| License | MIT |
| Role in ctxcop | Core detection library: ruleset translation, regex matching, codec decoding, Aho-Corasick keyword prefilter |

### Why we depend on it

betterleaks is the actively-maintained fork of gitleaks. We use its
detection engine (not its CLI), which gives us a battle-tested regex +
entropy filter pipeline that we'd otherwise have to write from scratch.
Rolling our own would mean reimplementing about 4,000 lines of careful
matching logic with no testing corpus advantage.

### Risk acknowledgment

Single-maintainer dep on a security-critical path. Acceptable
trade-off given:

1. The detection rules are embedded at compile time
   (`internal/rules/embedded/ctxcop.toml`). A poisoned upstream
   `gitleaks.toml` cannot reach a deployed ctxcop binary — verified
   in the v1.2.0 audit: `config/betterleaks.toml` is loaded via
   `//go:embed` upstream, and ctxcop doesn't invoke
   `NewDetectorDefaultConfig`.
2. The library is vendored at release via `go mod vendor`. If upstream
   is yanked or compromised, our existing release artifacts are
   unaffected.
3. Pin is exact (no float). Dependabot is excluded for this module.
4. We have a documented fork-readiness plan (see next subsection).
5. **Source consumption is via `go mod` against the commit SHA**, not
   the GitHub release tarball. This matters because v1.2.0's release-
   tarball sigstore attestations are unverifiable (upstream issue
   [betterleaks#134](https://github.com/betterleaks/betterleaks/issues/134),
   fixed in v1.3.0). `go.sum` content-hashing pins us to the audited
   bytes regardless of what happens to the upstream tag pointer.
6. **CI import-allowlist check** (added in Phase 2 of the OSS launch):
   the build fails if `vendor/github.com/betterleaks/betterleaks/{detect,
   config,report}/**` ever starts importing `os/exec`, `net/http`,
   `unsafe`, or `reflect`. The v1.2.0 audit verified those imports are
   absent today; the CI check catches regression on every bump.
7. **Per-release SHA re-verification.** The release pipeline asserts
   that `go.sum`'s entry for betterleaks resolves to the SHA recorded
   in this file's review log before producing a signed artifact.

### Fork-readiness plan

If betterleaks goes unmaintained, hostile, or yanked, we:

1. Fork to `webflow/betterleaks-pin` from the last reviewed-clean tag.
2. Add a `replace github.com/betterleaks/betterleaks =>
   github.com/webflow/betterleaks-pin v1.2.0` line in `go.mod`.
3. Cut a patch release with the replace directive.

Pre-staged read-only mirror is tracked as a roadmap item; once that
lands, the fork-and-cut becomes a one-hour exercise rather than a
one-week one.

### Review log

| Version | SHA | Date | Reviewer | Verdict | Detail |
|---|---|---|---|---|---|
| v1.2.0 | `296fee33358904c47d094fa6716347b223b2c13f` | 2026-05-20 | @arr-wf | **Pin with mitigations 5–7 above.** Source-level review clean (0 panics, 0 exec, 0 unsafe, 0 env-gated branches in 5,566 LoC of integration packages). Upstream-process risks (single-maintainer, self-merge PRs, lightweight tags) neutered by go.sum pinning, embedded ruleset, deliberate package-import discipline. v1.2.0 release tarballs themselves carry broken sigstore attestations (upstream #134); we don't consume those — source via go mod only. | [audits/betterleaks-v1.2.0.md](audits/betterleaks-v1.2.0.md) |

## Direct dependencies summary

| Module | Version | Maintainer posture | Notes |
|---|---|---|---|
| `github.com/BurntSushi/toml` | `v1.6.0` | Healthy multi-contributor project | Standard Go TOML library; minimal API surface we use. |
| `github.com/spf13/viper` | `v1.19.0` | Large project, well-maintained | Used only for ruleset parsing; we don't depend on most of its config-loading machinery. |
| `github.com/betterleaks/betterleaks` | `v1.2.0` | Single maintainer | See dedicated section above. |

## Transitive dependencies

The full transitive tree is documented in `NOTICES.md` with licenses
and upstream URLs. We do not audit transitive deps line-by-line; the
mitigations are:

- `govulncheck` runs daily and reachability-filters advisories to those
  that affect call paths actually exercised.
- `osv-scanner` runs daily for broader coverage of the OSV database.
- `go-licenses` in CI fails the build on non-MIT/Apache-2/BSD licenses
  showing up in the transitive tree.
- `go mod vendor` at release time produces an SBOM-checksummed snapshot.

## Adding a new direct dependency

PRs that introduce a new direct dependency require:

1. Entry in this file under "Direct dependencies summary" (or a
   dedicated section if it's a security-critical path).
2. License verification: must be MIT/Apache-2/BSD or already on the
   `NOTICES.md` allowlist.
3. Maintainer posture comment (single-maintainer adds a row to the
   risk-acknowledgment review pattern above).
4. CODEOWNERS-gated review from `@webflow/infrastructure-security`.

See `CONTRIBUTING.md` ("What we won't merge") for the rationale: we
prefer adding ~20 lines to internal code over pulling in a 500-line
library.
