# Security policy

ctxcop is a defensive security tool. Its trustworthiness *is* the product. We
treat vulnerability reports as our highest-priority work and the supply chain
of every released artifact as in-scope for the same scrutiny we apply to the
detection layer.

## Supported versions

| Version       | Supported          |
| ------------- | ------------------ |
| 0.x (latest minor) | Yes — security fixes back-ported as patch releases  |
| 0.x (one minor back) | 30-day grace after a new minor ships               |
| Older         | No — please upgrade |

The `v1.x` line will commit to a two-minor support window when it ships.

## Reporting a vulnerability

**Primary channel:** [GitHub Private Security Advisory](https://github.com/webflow/ctxcop/security/advisories/new).
Opening a PSA gives us a private collaboration space, lets GitHub act as the
CVE Numbering Authority, and tracks the advisory's lifecycle in one place.
This is the recommended path.

**Backup channel:** `security@webflow.com`. Use this if you don't have or
don't want a GitHub account, or if the PSA flow is otherwise blocked. The
mailbox is monitored by Webflow's Security team; reports are
triaged within the SLA below regardless of which channel arrives first.

Please do *not* file vulnerability reports as public GitHub issues, comments
on PRs, or chat messages on community channels. We will redirect any such
report to the PSA flow and ask you not to discuss the issue publicly until
the embargo lifts.

When you report, include:

- Affected ctxcop version (output of `ctxcop --version`).
- Affected harness (Claude Code / Codex / Cursor / Pi / OpenCode / multiple).
- Minimal reproducer: ideally a JSON payload to a specific hook subcommand
  plus the observed-vs-expected behavior.
- Severity assessment if you have one, with rationale.
- Any time pressure (e.g., you found this during a paid engagement and
  reporting timelines apply on your end too).

## Response SLA

We commit to:

- Acknowledge your report within **3 business days**.
- Provide initial triage assessment within **7 business days** (severity,
  scope, planned response).
- Ship a fix, or document "won't fix" with rationale, within **30 days** for
  High and Critical severity issues. Medium and Low track on a best-effort
  basis with status updates on the PSA thread.

Missing an SLA without prior communication is itself a process bug; please
ping the PSA thread or `security@webflow.com` if we've gone silent.

## In scope

Reports we consider security-relevant:

- **Detection bypasses** — a credential-shape value reaches the model's
  context window through any documented hook path despite a ruleset rule
  that should have caught it.
- **Signing/verification flaws** — release artifacts that don't verify
  against their cosign signature, attestation chains that don't resolve to
  the expected workflow identity, SBOMs that misrepresent the binary
  contents.
- **Install-time path or argument traversal** — `ctxcop install` or
  `uninstall` writing or deleting files outside the documented harness
  config paths.
- **Hook-handler open-fails** — ctxcop crashes or otherwise returns an
  empty decision in a path where it should have blocked, allowing a
  credential to flow through.
- **Redaction off-by-ones** — placeholder substitution that leaks a partial
  credential (last-4 leaked beyond the documented fingerprint length,
  for example).
- **Audit-log tampering** — log entries that can be silently mutated or
  deleted while ctxcop reports a clean state.
- **Supply-chain bypass** — workflow misconfigurations that would let a PR
  publish a signed release without passing the release approval gate.
  (Note: the gate is currently a single required reviewer, not two-person
  review. Its known limits are documented at the `environment: release`
  step in `.github/workflows/release.yml` and are not a finding.)

## Out of scope (for embargo)

These are in-scope for *public* issues — open one and tag it `triage` — but
they aren't embargo-worthy:

- Regex tightening or new credential-pattern rule requests.
- False positives in the default ruleset.
- Performance issues, including pathological-input slowdowns that don't
  cross into credential-leak territory.
- Documentation gaps or unclear error messages.
- ctxcop crashing where a crash is failsafe (the harness sees a
  passthrough; no credential reaches the model).
- Detections from synthetic fixture credentials (see
  [fixture-credential namespace](#fixture-credential-namespace) below).

## Out of scope (entirely)

- Endpoint compromise — a malicious actor with code execution on the
  developer's machine can do anything ctxcop can. ctxcop is not a sandbox.
- Compromised MCP servers — ctxcop redacts data in and out of MCP, but a
  compromised MCP server is a separate trust boundary owned by the MCP
  server author.
- Model side-channel inference of credentials from non-credential context.
- Social engineering: a user being convinced to paste a credential.
  ctxcop's `UserPromptSubmit` blocks the obvious case; defense-in-depth on
  top of that is the user's responsibility.

## Embargo policy

Default embargo is **90 days from acknowledgment**, or coordinated public
release at our discretion if a fix ships sooner. Extensions are granted
only for upstream-coordinated multi-party issues (e.g., a flaw in
betterleaks that affects multiple downstreams).

If you intend to publish a writeup or talk after the embargo, please loop
us in 30 days before so we can prepare a coordinated advisory release.

## CVE assignment

GitHub is a CVE Numbering Authority for repositories under its umbrella,
and we request CVEs through the GitHub PSA interface. We do not run our
own CNA. In the rare case GitHub declines to assign, we'll request directly
through MITRE.

## Advisory publication

When a fix is ready, we:

1. Merge the fix to a private fork branch tied to the PSA.
2. Cut a coordinated release tag with the fix included.
3. Publish the PSA with the assigned CVE, credit to the reporter (see
   below), and a clear "affected versions / fixed versions" range.
4. Add an entry to `CHANGELOG.md` under a Security section.
5. Post a release-notes update via the `@ctxcop` GitHub releases atom feed.

## Reporter credit

We don't run a monetary bug bounty for this software. We do credit reporters in:

- The published GitHub advisory.
- The `CHANGELOG.md` entry for the fix release.
- A `THANKS.md` file in the repo root (once we have entries to populate it
  with).

If you'd rather *not* be credited, say so in the PSA and we won't.

## Fixture-credential namespace

Test fixtures used to exercise ctxcop's detection rules contain synthetic
credentials such as `AKIA...LALEMEL33243OLIA`, `ghp_0123456789...`, and
similar shapes. These values are also matched by the embedded skip-list
(`internal/skiplist/skiplist.go` defaults: `testdata/`, `fixtures/`,
`*_test.*`, etc.) so they don't fire on real-world scans.

Please do not report fixture detections in `*_test.go` or `testdata/` as
vulnerabilities. If you find a fixture *outside* the skip-list path that
contains an apparent credential, that's a real report we want to hear.

## Build integrity

Releases are currently source-only — v0.1.0's prebuilt macOS binaries
were ad-hoc/linker-signed only, which Gatekeeper rejects outright once
a binary's been through a download/quarantine flow. We're enrolled in
the Apple Developer Program; codesigning + notarization aren't wired
into the release pipeline yet. Build from source per the README, or
`go install github.com/webflow/ctxcop/cmd/ctxcop@latest`, neither of
which is affected (Gatekeeper only rejects downloaded, quarantined
binaries, not ones you build locally).

Once prebuilt binaries return, they'll again be signed with
[Sigstore cosign](https://github.com/sigstore/cosign) in keyless OIDC
mode (signing identity is the workflow path at a tag, e.g.
`https://github.com/webflow/ctxcop/.github/workflows/release.yml@refs/tags/vX.Y.Z`)
plus CycloneDX + SPDX SBOMs and GitHub-native attestations — that
pipeline is intact in git history and just needs the codesigning step
added back in front of it.

Builds are bit-for-bit reproducible given the same git tag and Go
toolchain (pinned via `go-version-file: go.mod`) — see
[docs/verify-reproducibility.md](docs/verify-reproducibility.md) for
the paste-and-run script.

## Audit-log integrity

ctxcop's optional audit log (`$CTXCOP_AUDIT_LOG`, off by default)
records every redaction event as a JSONL line. Each entry carries a
`prev` field linking back to the previous entry's `hash`, forming a
tamper-evident chain across appends.

To verify the chain at any point:

```sh
ctxcop audit verify --log /path/to/audit.jsonl
```

The subcommand walks the log, recomputes each entry's SHA-256, and
checks every `prev` links to the prior entry's `hash`. Tampered fields
(hash mismatch) and removed or reordered entries (chain break) are
reported by line number. Legacy entries (no `hash`, predating the
hash-chain feature) are surfaced separately and don't fail the check; the chain
resumes from the next chained entry.

What the chain catches:

| Attack | Detected by |
| --- | --- |
| Field rewritten in place | hash mismatch on that line |
| Whole entry removed | chain break on the following line |
| Entries reordered | chain break on the first out-of-order line |
| Whole tail truncated | not detected by `verify` alone — pair with off-host log shipping if that's in your threat model |

If you suspect audit-log tampering in a deployment, that's a high-
severity report; please file via PSA.

## Threat model

See [THREATMODEL.md](THREATMODEL.md) for the explicit trust model, the
known bypass classes (we publish them), and the verification claims that
do and don't hold.
