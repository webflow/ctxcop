# GitHub Actions pin policy

This file is normative: every workflow under `.github/workflows/` and
every `uses:` line in any reusable workflow we import follows these
rules. The CODEOWNERS rule for `.github/workflows/*` and this file
requires `@webflow/infrastructure-security` review on any change.

The rules exist because the 2025 supply-chain incident class — most
prominently the tj-actions/changed-files compromise in March 2025 —
demonstrated that a re-tag on a popular action can land malicious code in
thousands of CI runs within hours. SHA pinning is the primary defense.

These rules are enforced by the platform, not only by review. The
repository's Actions policy is set to `selected` with an explicit
allowlist (GitHub-owned actions plus the two third-party actions named
in `action-allowlist.txt`), and `sha_pinning_required` is enabled, so an
unpinned or non-allowlisted `uses:` fails before the workflow runs.
CODEOWNERS review on `.github/workflows/*` and on this file is the
second layer.

## Rules

1. **Pin every `uses:` to a full 40-char commit SHA, never a tag.**
   Format:
   ```yaml
   - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd  # v6.0.2
   ```
   The `# vX.Y.Z` comment is what Dependabot pattern-matches on to
   propose SHA bumps; keep it accurate.

2. **Prefer first-party (`actions/*`, `github/*`) over third-party.**
   A compromise of an `actions/*` repo is a GitHub-platform-level
   incident with broad detection. A compromise of a no-name marketplace
   action is a Tuesday and may go unreported.

3. **Minimize wrapper actions.** Prefer a `run:` step that installs the
   tool from a checksum-verified release tarball over a vendor's
   wrapper action. Wrappers add attack surface for marginal ergonomic
   benefit. The list below is mechanical — it names wrappers whose
   underlying tool we either already invoke directly or have chosen not
   to run at all. It is not an assessment of those projects' quality or
   security. Do not introduce:
   - `golangci/golangci-lint-action`
   - `securego/gosec` (the action; the CLI is fine via `go install`)
   - `aquasecurity/trivy-action`
   - `gitleaks/gitleaks-action`
   - `goreleaser/goreleaser-action`
   - `peter-evans/create-pull-request` (use `gh api`/`gh pr` instead)

4. **Trivy is a hard no for this repo.** Replaced by `govulncheck`
   (Google first-party, reachability-aware, Go-native) plus
   `osv-scanner` (Google first-party, broader OSV database). Both are
   single binaries we install and invoke via `run:`.

5. **Self-scan for credentials.** ctxcop is a credential scanner; we
   scan ourselves with ourselves. No `gitleaks-action` or third-party
   secret-scan action.

6. **Minimal token permissions.** Set `permissions: contents: read` at
   the workflow root. Escalate per-job, only as needed
   (`id-token: write` for cosign keyless OIDC; `contents: write` only
   on the publish job). Never `permissions: write-all`.

7. **No `pull_request_target`.** It runs PR code with write tokens —
   the moment a forked PR exists, that's exploitable. Use
   `pull_request`; for forks the workflow runs from the base ref's
   workflow file with read-only tokens.

8. **Reusable workflows: only the SLSA generator, and SHA-pinned.**
   `slsa-framework/slsa-github-generator` is the rare third-party
   reusable workflow with sound provenance (isolated runners,
   Sigstore-verified identities, Google + Chainguard + Linux Foundation
   collaborators). All other release steps inline.

9. **Org/repo Actions allowlist.** Repository settings → Actions →
   "Allow specified actions and reusable workflows" restricts the set
   to the explicit list in `action-allowlist.txt`. Adding a new action
   requires a PR to that file, which CODEOWNERS routes to security
   review.

10. **Dependabot watches Actions too.** `.github/dependabot.yml`
    includes a `github-actions` ecosystem block so a CVE-driven bump
    of (say) `actions/checkout` opens a PR within a week.

## When in doubt

If you're about to add a `uses:` line and aren't sure whether it
follows these rules, the answer is probably "ask first." Open a draft
PR with `[discussion]` in the title and tag
`@webflow/infrastructure-security`.

## Why this is in a separate file

The rationale changes slowly (an incident class stays an incident
class for years); the workflow files change every week. Keeping the
policy text out of inline workflow comments means we update it once
and reviewers can read it once.
