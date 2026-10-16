# Changelog

All notable changes to ctxcop are documented here, in the
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format with
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

For each release, sections appear in this order when applicable: **Security**
(separated first because it's why people read changelogs of security tools),
**Added**, **Changed**, **Fixed**, **Removed**, **Deprecated**.

This file starts at ctxcop's first public release. The private
development history behind it — four internal release lines plus a
hardening pass done ahead of open-sourcing — is preserved in
[docs/dev-log/CHANGELOG-pre-1.0.md](docs/dev-log/CHANGELOG-pre-1.0.md).

## [Unreleased]

## [0.1.2] — 2026-10-27

### Security
- **Go toolchain bumped to 1.26.10** for GO-2026-6809 (`crypto/x509`,
  reachable from ctxcop's code, fixed in 1.26.10) and GO-2026-6617 (HTTP/2
  server crash from an HPACK encoder race in `net/http`, fixed in 1.26.9).
- **Vulnerable indirect dependencies bumped.** govulncheck found none of
  these reachable from ctxcop's code; they're patched anyway:
  `github.com/google/cel-go` v0.30.0 (GO-2026-6094), `golang.org/x/text`
  v0.41.0 (GO-2026-5970, GO-2026-6629), `github.com/klauspost/compress`
  v1.18.7 (GO-2026-5841), and `golang.org/x/crypto` v0.56.0 (GO-2026-6303,
  GO-2026-6354, GO-2026-6355). GO-2026-5932 (the unmaintained
  `x/crypto/openpgp` package) has no fixed version; ctxcop doesn't import it.

### Added
- **Redis AUTH detection: four embedded rules covering the leak shapes
  upstream has no answer for.** A bare Redis password has no token prefix
  and no key=value shape — the two forms gitleaks-class rules detect — so
  the plain AUTH command line as error logs show it, the node-redis
  structured error form (args array and JSON), redis-cli `-a`/`--pass`
  invocations, and RESP protocol dumps (raw CRLF, escaped, space-flattened)
  all passed through unredacted. Rules are ported rule-for-rule from
  [webflow/secrets-scrubber](https://github.com/webflow/secrets-scrubber)
  (Santiago Moreno), whose project was built around a real Redis key leak
  into an AI session; RE2 forbids its JS lookaheads, so its
  reference-value heuristic became a per-rule CEL filter. Every rule
  carries a minimum-length floor (16 for plain AUTH, 8 elsewhere) — a
  sub-8-char finding trips Splice's over-redact backstop against
  unrelated lines carrying the same short form. Port deviation: the RESP
  rule requires the `*N` array header (all of secrets-scrubber's RESP
  fixtures carry it) so prose dollar-amounts near the word auth do not
  redact.

### Fixed
- **Hooks drain stdin before exiting.** A paused hook (or one with an off
  switch set) returned without reading its input, so a bridge writing a
  payload over the pipe buffer (~64KB) got EPIPE and crashed the host. The
  pi and opencode bridges also handle stdin errors now.

## [0.1.1] — 2026-08-27

### Security
- **OpenCode: `output.metadata` is now redacted, not just `output.output`.**
  `tool.execute.after`'s `output` has three independently-mutable fields —
  `title`, `output`, `metadata` — and OpenCode populates `metadata` with a
  raw copy of the tool's result, persisted to the session store and
  included in `--format json` / `opencode export`, independent of
  `output.output`. ctxcop's bridge only ever redacted `output.output` (the
  field the model reads next turn), so a secret fully redacted in what the
  model saw could still sit in plaintext in session metadata. Confirmed
  live against a real OpenCode session: `output.output` came back clean
  while `output.metadata.output` still carried the raw AWS/GitHub/OpenAI/
  Anthropic-shaped fixtures. `metadata` is now walked and redacted via the
  same tree-walker the claudecode/cursor/pi adapters already use for their
  tree-shaped payloads. (#9)

### Removed
- **Prebuilt release binaries.** v0.1.0's macOS binaries were only
  ad-hoc/linker-signed, which Gatekeeper rejects outright once a binary
  has been through a download/quarantine flow. We're enrolled in the
  Apple Developer Program but codesigning + notarization aren't wired
  into the release pipeline yet, so releases are source-only
  (`go install` or build from source) until that lands. The
  build/cosign/SBOM/attest pipeline that produced v0.1.0's binaries is
  intact in git history and will come back once the cert is in place.

## [0.1.0] — Unreleased

ctxcop's first public release.

### Added
- Six harness adapters — Claude Code, Codex CLI, Cursor, Pi (pi.dev),
  OpenCode (sst/opencode), and Aider — each wired via
  `ctxcop install --harness=<name>` (or autodetect) with a symmetric
  `uninstall`.
- Credential-redaction engine: keyword-gated regex rules layered on
  betterleaks defaults, a shared JSON/tree walker across every hook
  payload shape, a skip-list for intentional fixtures, and
  encoding-evasion normalization (zero-width stripping, delimited-hex
  collapsing, HTML-entity decoding). Splicing is buffer-consistent and
  a redaction is only ever reported after the secret is confirmed
  absent from the output.
- Tamper-evident audit log: SHA-256 hash-chained entries with a
  `ctxcop audit verify` subcommand that reports tampering or chain
  breaks by line number, with correct cross-process locking on Linux,
  macOS, and Windows.
- `ctxcop pause` / `resume`, honored across every harness's
  decision-producing hooks, with a one-line "PAUSED" notice on session
  start and each user turn so a forgotten pause isn't silent.
- Cross-platform support: Linux, macOS, and Windows, all verified
  against the real `windows-latest` CI runner.
- Pure-OIDC release pipeline: reproducible per-platform builds,
  CycloneDX + SPDX SBOMs, cosign keyless signing (Sigstore
  Fulcio/Rekor), SLSA build-provenance and SBOM attestations, and a
  release-tag gate restricted to allowed signers.
- Opt-in PII/DLP example ruleset (`examples/rules/pii-dlp.toml`) for
  crypto-wallet and financial-PII patterns, off by default.

### Security
- Redaction correctness hardening carried out ahead of this release:
  a redaction is never attested unless the secret is confirmed absent
  from the output; inline `gitleaks:allow` / `ctxcop:allow` markers are
  honored only on developer-authored content, never on untrusted tool
  output; streaming redactions are logged and audited like buffered
  ones; secrets of 12 characters or fewer render without a disclosing
  `:last4` tail and no longer over-trigger whole-payload redaction;
  redacted-copy temp files are written to validated, non-predictable
  paths, including validation of the shared parent directory.
  Go toolchain kept current against stdlib CVEs `govulncheck` flags as
  reachable from ctxcop's code.
- Full line-by-line detail, including issue references, is in the
  [pre-1.0 dev log](docs/dev-log/CHANGELOG-pre-1.0.md).

[0.1.2]: https://github.com/webflow/ctxcop/releases/tag/v0.1.2
[0.1.1]: https://github.com/webflow/ctxcop/releases/tag/v0.1.1
[0.1.0]: https://github.com/webflow/ctxcop/releases/tag/v0.1.0
