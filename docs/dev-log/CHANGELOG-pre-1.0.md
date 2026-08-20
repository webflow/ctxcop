# Pre-1.0 dev log

This is the version-by-version history of ctxcop's private development,
from the first internal release through the hardening pass done ahead
of open-sourcing. It predates the public repository and its version
numbers (0.1.0–0.4.0) are internal — the public repo's own history
starts over at [0.1.0](/CHANGELOG.md). Kept here for anyone who wants
the full line-by-line rationale behind what shipped; the top-level
[CHANGELOG.md](/CHANGELOG.md) is the canonical one going forward.

Documented in the
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format with
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

For each release, sections appear in this order when applicable: **Security**
(separated first because it's why people read changelogs of security tools),
**Added**, **Changed**, **Fixed**, **Removed**, **Deprecated**.

## [Unreleased]

### Security
- **Go toolchain bumped to 1.26.6.** 1.26.5 carried five stdlib CVEs
  (`GO-2026-6218` net/url, `GO-2026-6090` crypto/tls, `GO-2026-6088`
  encoding/xml, `GO-2026-5972` encoding/asn1, `GO-2026-5026` net/http via
  x/net/idna) that `govulncheck` flags as reachable from ctxcop's code —
  mainly through `internal/redact`'s detector and the harness adapters'
  stdio handling. No ctxcop code changed; `go.mod`'s `go` directive is the
  only diff.
- **Redacted-copy temp files no longer trust a pre-existing shared parent.**
  `$TMPDIR/ctxcop` was created with `MkdirAll`, which silently accepts a
  directory of any owner or mode — including a symlink another local user
  planted first, redirecting every redacted copy into a directory they
  control. #48 hardened the per-file write; the parent stayed trusted. The
  new `internal/securetemp` validates it (no symlink, a directory, not
  group/other-writable, owned by the current uid) and falls back to an
  unpredictable directory directly under `$TMPDIR` when validation fails —
  failing closed there would make callers skip redaction and pass the
  original file through, leaking the raw secret. (#82)
- **Placeholders no longer disclose short secrets.** The `:last4`
  fingerprint was emitted for any secret of any length, so at four
  characters or fewer the "last 4" *was* the whole secret — a short DSN
  password was reproduced verbatim inside the placeholder that was supposed
  to hide it, and at five or six characters most of it was. Secrets shorter
  than 12 characters now render as `<REDACTED:<rule-id>>` with no tail.
  `SECURITY.md` lists fingerprint over-disclosure as in-scope. (#83)
- **Short secrets no longer destroy unrelated tool output.** The #45
  verify-after-splice step treated any residual substring occurrence as a
  surviving secret. Two things made that fire spuriously: the placeholder
  itself contained the secret (above), so the check could never clear; and a
  short capture collides with ordinary prose — `pass` occurs inside
  `password` and `passthrough`. The result was escalation to whole-payload
  over-redaction, silently discarding every unrelated line. A command whose
  output contained a DSN with a short password lost the entire output.
  The check now ignores occurrences inside ctxcop's own placeholders, and
  for forms of 12 characters or fewer requires a token boundary. Longer
  forms keep the plain substring check, so an abutted 40-character secret is
  still caught — under-detection remains the wrong failure direction. (#83)
- **AWS secret access keys are detected regardless of label casing.** The
  `ctxcop-aws-secret-access-key` rule matched only underscore-separated
  labels, so `awsSecretAccessKey` — the spelling most common in JS/TS
  config objects and JSON bodies — passed through unredacted. Word
  separators are now optional, covering snake_case, kebab-case, and
  camelCase. The keyword prefilter was widened in step: it matches literal
  substrings of the lowercased content, so the separator-free spelling was
  unreachable via the old `aws_secret` keyword regardless of the regex.
  Reported by the Cursor review bot on #64.
- **Database URIs with a password but no username are detected.** The
  `ctxcop-db-connection-uri` rule required at least one character in the
  username position, missing the shape redis and amqp use routinely, where
  the userinfo begins directly with the colon. The username quantifier is
  now `*`; the trailing `@` still keeps credential-less DSNs
  (`postgres://host:5432/db`) from matching. Reported by the Cursor review
  bot on #64.

### Fixed
- **Windows test suite.** `windows-latest` was dropped from `ci.yml`'s
  test matrix because `TestInstall*` in claudecode/codex/cursor panicked
  with `interface conversion: nil → map[string]any`, and
  `TestPreToolUseRedirectsReadWithSecret` returned `{}` instead of
  `permission:allow`. Root causes were entirely in the test suite, not
  production code: `os.UserHomeDir()` reads `%USERPROFILE%` on Windows
  and never falls back to `$HOME`, and `os.TempDir()` reads
  `%TMP%`/`%TEMP%`/`%USERPROFILE%` and never falls back to `$TMPDIR` —
  so the standard `t.Setenv("HOME", dir)` / `t.Setenv("TMPDIR", dir)`
  test-isolation pattern silently redirected nothing on that platform.
  Separately, several fixtures hand-built JSON by concatenating a raw
  filesystem path into a string literal; a Windows path's backslashes
  are JSON escape characters, so the resulting literal failed to parse
  and ctxcop's fail-open behavior returned `{}`. New `internal/testenv`
  package (`SetHomeDir`, `SetTempDir`, `JSONString`) fixes both classes
  at every call site. Running the fix against the real `windows-latest`
  CI runner surfaced the same HOME-isolation bug in `internal/pause`
  and `internal/rules` (not caught by the initial Wine-based
  reproduction, which only covered the harness packages) — fixed the
  same way.
- **`internal/audit` cross-process locking on Windows.** Unlike the
  test-only issues above, this was a real gap: `lock_other.go`
  (`//go:build !unix`) made the audit log's cross-process advisory
  lock a no-op on every non-Unix platform, including Windows, so
  concurrent hook processes could race on the hash-chain's
  read-Prev-then-append and corrupt it (`TestConcurrentMultiProcessChain`
  failed with hundreds of broken chain links on real Windows CI). New
  `lock_windows.go` implements the same guarantee via
  `golang.org/x/sys/windows.LockFileEx` (already an indirect
  dependency, now promoted to direct) — Windows' equivalent of
  `flock(2)`. Verified under Wine before and after.
  Verified by cross-compiling the affected packages'
  test binaries for `windows/386` and running them under Wine, before
  and after the fix. `windows-latest` is back in `ci.yml`'s test matrix.

## [0.4.0] — 2026-07-31

The 0.4.0 line completes the pre-open-source hardening pass and adds the
sixth harness adapter. It rolls up the security-hardening work first cut
as 0.4.0-rc.1 (from an internal review — every finding reproduced against
the built binary and covered by a regression test), the Aider adapter,
and a round of detection improvements driven by an external benchmark,
[agent-egress-bench](https://github.com/luckyPipewrench/agent-egress-bench)
(evaluation and content-layer-vs-network-layer scope boundary in
[docs/agent-egress-bench.md](docs/agent-egress-bench.md)). The new
detection was gated to add zero new false positives on the benchmark
allow-set and zero new redactions on a realistic normal-agent-flows
suite (OAuth, MCP auth, session cookies).

### Added
- **Aider (Aider-AI/aider) harness adapter.** ctxcop now integrates
  with Aider, taking the supported-harness count from five to six.
  Aider is structurally different from every other harness ctxcop
  supports: it has no hook system, no callback API, no MCP surface,
  no sub-agent surface, no tool-call lifecycle. The PR that would
  have added Claude-Code-style hooks
  ([Aider-AI/aider#4485](https://github.com/Aider-AI/aider/pull/4485))
  was closed with the maintainer noting Aider is in maintenance mode;
  the corresponding feature request
  ([#5300](https://github.com/Aider-AI/aider/issues/5300)) was closed
  unimplemented. The ctxcop adapter therefore integrates via **static
  configuration** in `.aider.conf.yml` rather than runtime events:
  - `ctxcop install --harness=aider` rewrites existing `lint-cmd` /
    `test-cmd` values through `<ctxcop> run [--stream] -- bash -c
    '<original>'` (streaming for tests), so the entire original
    command — including compound commands and env-var/`cd` prefixes —
    keeps its shell semantics and its combined output flows through
    the redactor before Aider feeds it back to the model. The
    `<language>:` prefix on lint-cmd entries is preserved, matching
    Aider's own no-space-required grammar. Idempotent; unrelated YAML
    keys survive.
  - A SessionStart-equivalent priming file is written to
    `~/.aider/ctxcop-priming.md` and added to `.aider.conf.yml`'s
    `read:` list, so every future Aider session opens with the
    model having seen ctxcop's env-var / `<REDACTED:…>` conventions.
  - A new manual `ctxcop hook aider preflight [--project-root <path>]`
    subcommand scans the project's `.env` for credential-shape values
    and stderr-warns if any exist. The priming file suggests the
    shell alias `alias aider='ctxcop hook aider preflight && aider'`.
  - Coverage is narrower than the hook-based adapters and the delta
    is called out prominently in
    [docs/harnesses.md#aider](docs/harnesses.md#aider) and
    [docs/known-limits.md](docs/known-limits.md#aider): no
    `UserPromptSubmit`-equivalent, auto-detected linters bypass the
    wrap, LLM-emitted edit blocks bypass ctxcop, and no LiteLLM
    callback interposition (blocked upstream; tracked in ROADMAP).
- **Opt-in PII/DLP example ruleset** (`examples/rules/pii-dlp.toml`).
  Crypto-wallet (BTC/ETH/xpub/WIF/seed-phrase) and financial-PII
  (credit-card, IBAN, SSN, bank routing/account) rules, loaded via
  `CTXCOP_RULES` — off by default, keeping ctxcop's default scope
  credential-focused. Doubles as a worked example of extending detection
  with user-supplied rules. (#63)

### Security
- **Redaction never falsely attests a removal (CRITICAL).** The engine
  could report a secret as redacted — writing `action:"redacted"` to
  the audit log and telling the model a placeholder was substituted —
  while the secret survived in the output. Two causes: decoded
  (base64/hex/percent) findings spliced with offsets computed against
  a different buffer, and rule IDs attested without verifying the
  splice changed anything. Splicing is now buffer-consistent and
  position-independent, and a rule is reported redacted only after the
  secret is confirmed absent (over-redacting the line, then the whole
  payload, if needed). (#45)
- **Untrusted tool output no longer honors inline allow-markers.**
  `gitleaks:allow` / `ctxcop:allow` / `ctxcop:fixture` in a Bash output
  stream, a WebFetch/MCP response, a read file, or a compaction
  transcript no longer suppresses redaction — a marker there could be
  planted by an attacker or a stray `sed`. Markers are honored only on
  developer-authored content (`ctxcop scan`, Write/Edit, prompt/command
  scans), now bounded to the finding's physical line and audited when
  they suppress. (#56)
- **Streaming redactions are now logged and announced.** Redactions on
  `ctxcop run --stream` output (auto-selected for backgrounded Bash)
  previously emitted no operator notice and wrote no audit entry,
  unlike the buffered path. (#58)
- **PreToolUse no longer bypasses the user's permission system.** The
  Claude Code adapter returned `permissionDecision:"allow"` on every
  Bash/Read/Agent call, converting the user's per-call prompt/deny
  rules into unattended auto-run. It now rewrites input via
  `updatedInput` and omits the decision, so the user's own permission
  rules still govern. (#47)
- **Write/Edit secret-blocking bypasses closed.** Secrets in a Bash
  command (heredoc, `curl -H "Authorization: Bearer …"`) and in
  `MultiEdit`'s nested `edits[]` slipped past the Claude Code adapter;
  the command is now scanned (deny-with-guidance, matching cursor/codex)
  and write-shaped payloads are detected by shape rather than a stale
  tool-name allowlist. (#49)
- **Redacted-copy temp files hardened.** The Read-redirect temp files
  used a predictable path in a world-writable directory written with a
  symlink-following call, allowing arbitrary-file overwrite / context
  injection. Now written to a fresh per-invocation directory with
  `O_CREATE|O_EXCL`, in both the Claude Code and Cursor adapters. (#48)
- **Project `.ctxcop.toml` overrides are now surfaced.** A repo-supplied
  config could disable rules or broaden skip-paths silently, and
  `ctxcop rules list` reported the pre-override state. Project-scope
  overrides now emit a warning + audit entry, and `rules list` shows
  the effective state and flags overridden rules. (Project config keeps
  its override power; user/env scope stays silent.) (#46)
- **Audit hash-chain no longer false-positives under concurrency.**
  Parallel hooks (separate processes) could each chain off the same
  `lastHash`, making `ctxcop audit verify` report breaks on an honest
  log. Appends are now serialized with a cross-process `flock`. (#57)
- **Go toolchain `1.26.4` → `1.26.5`** to close two called stdlib
  advisories `govulncheck` flags:
  [GO-2026-5856](https://pkg.go.dev/vuln/GO-2026-5856) (`crypto/tls`
  Encrypted Client Hello privacy leak) and
  [GO-2026-4970](https://pkg.go.dev/vuln/GO-2026-4970) (`os`); plus
  `golang.org/x/crypto` `v0.46.0` → `v0.52.0` (with `x/sys`/`x/sync`/
  `x/text` ripple) for the uncalled module-level advisories. (#32)
- **`github.com/google/cel-go` `v0.27.0` → `v0.29.0`** (transitive via
  betterleaks) to clear [GHSA-gcjh-h69q-9w9g](https://github.com/advisories/GHSA-gcjh-h69q-9w9g),
  flagged by `osv-scanner`. (#42)
- **Encoding-evasion normalization.** Detection now also runs over
  zero-width-stripped, delimited-hex-collapsed, and HTML-entity-decoded
  views of each line, catching a credential hidden by those obfuscations
  and over-redacting the whole line — kept #45-safe (no attestation
  until the secret is confirmed gone). (#62)
- **New keyword-gated credential rules** for AWS secret access keys,
  database / URL connection credentials (`scheme://user:pass@`),
  SendGrid keys, and HTTP Basic-auth headers — each gated to avoid the
  bare-high-entropy false-positive traps. (#64)

### Changed
- CI/release GitHub Actions bumped to current pinned digests:
  `actions/setup-go` `v6.5.0` → `v7.0.0` (#35), `actions/checkout`
  `v7.0.0` → `v7.0.1` (#38), and `github/codeql-action`
  (`analyze`/`init`/`upload-sarif`) `v4.36.x` → `v4.37.3`
  (#39, #40, #41). All remain 40-char SHA-pinned with version comments.
- Removed Homebrew/tap references from public-facing docs — install via
  the private tap isn't relevant to a public audience. (#44)

### Fixed
- Corrected the README provenance claim to SLSA Build **L2** (the
  pipeline produces L2, not L3), and fixed the install `curl` one-liner
  and `SECURITY.md` verify command, which generated artifact filenames
  that 404'd on every platform. (#50, #51)

## [0.3.0] — 2026-07-02

The 0.3.0 line extends ctxcop past the JSON-hook harnesses into
embedded-TypeScript-bridge agents. Pi (pi.dev) and OpenCode
(sst/opencode) adapters land, each shipping a small `go:embed`'d TS
bridge the host runtime auto-discovers — jiti-transpiled for Pi,
Bun-native for OpenCode — with no npm package and no build step. The
supported-harness count goes from three to five. Alongside the harness
work: a tamper-evident audit-log hash chain surfaced through a runnable
`ctxcop audit verify`, a paste-and-run reproducibility verifier that
lets downstream consumers rebuild a tag and diff the sha256 themselves,
a Claude Code elicitation-schema fix that restores the operator-facing
notice and audit fields, a README/docs restructure, and a pre-release
harness-catchup pass: Claude Code's PostToolUse hook now redacts tool
output in place instead of only warning about it, and two real OpenCode
coverage gaps (the newer `websearch` tool, a misclassified `apply_patch`)
are closed. All five harness adapters were re-verified end-to-end
against their current released versions before this tag.

### Security
- **Go toolchain bumped `1.26.3` → `1.26.4`** to close two standard-
  library advisories flagged by osv-scanner:
  [GO-2026-5037](https://osv.dev/GO-2026-5037) and
  [GO-2026-5039](https://osv.dev/GO-2026-5039). Directive lives in
  `go.mod`; CI and the release pipeline both resolve the toolchain via
  `go-version-file: go.mod`, so the published binaries build against the
  patched stdlib.
- **Claude Code PostToolUse now redacts in place** instead of only
  emitting a soft notice. Claude Code 2.1.x added
  `hookSpecificOutput.updatedToolOutput`, which replaces a tool's
  result for every tool (not just MCP) — confirmed against both the
  published hooks reference and the installed 2.1.198 binary's own
  source. Previously, a secret surfacing through a non-Bash/non-Read
  tool response (WebFetch, MCP, a subagent's own output) fully entered
  the model's context; ctxcop could only warn after the fact. ctxcop
  now splices `<REDACTED:…>` placeholders into a copy of the response
  and returns it via `updatedToolOutput`, keeping the notice as a
  fallback for older clients or tools the rewrite doesn't reach.

### Added
- **Tamper-evident audit log chain + `ctxcop audit verify` subcommand**.
  Each audit-log entry now carries a `prev` field linking back to the
  previous entry's `hash` (SHA-256 over the canonical entry minus the
  `hash` field itself). `ctxcop audit verify --log <path>` walks the
  log, recomputes each hash, and verifies every `prev` links to the
  prior entry's `hash`. Reports tampered fields (hash mismatch) and
  removed/reordered entries (chain break) by line number. Legacy
  entries from pre-chain versions are surfaced separately and don't
  fail the check; the chain resumes from the next chained entry.
  Surfaces the "Audit-log integrity" claim in SECURITY.md as a
  runnable check rather than a documented promise.
- **`docs/verify-reproducibility.md`** — paste-and-run shell script
  that rebuilds a tagged release from source and compares the local
  sha256 against the published artifact. Removes "trust our CI in
  isolation" as a requirement for downstream verifiers. Companion
  to the cosign verification command in SECURITY.md — together they
  catch different attack classes (CI compromise vs. unsigned/swapped
  binary).
- **Pi (pi.dev) harness adapter** under `internal/harness/pi/`.
  Three events: `before_provider_request` (the load-bearing
  chokepoint — redacts the full LLM HTTP payload before send),
  `before_agent_start` (one-time priming injection into the system
  prompt), and `tool_call` (blocks MCP tool calls whose input
  contains credentials). The adapter ships a `<50-line TypeScript
  bridge embedded via `go:embed`; Pi auto-discovers it from
  `~/.pi/agent/extensions/` and transpiles it on load via jiti.
  No npm package, no build step. Verified against Pi 0.75.4, re-
  verified against 0.80.3 before this tag — no breaking changes to
  the event shapes ctxcop depends on.
  `ctxcop install --harness=pi` writes the bridge file; the
  autodetect probe also picks up `pi` when `~/.pi/` is present.
- **OpenCode (sst/opencode) harness adapter** under
  `internal/harness/opencode/`. Two events:
  `tool.execute.before` (blocks exfil-class tools — `webfetch`,
  `websearch`, and MCP-style underscore-named tools — whose args
  contain credential-shape data) and `tool.execute.after` (redacts
  the tool output string for every tool — the catch-all that covers
  bash captures of secrets in env, `.env` file reads, MCP tool
  results, etc.). Local tools (bash/read/write/edit/`apply_patch`/
  grep/glob/ls) passthrough at the before hook by design — their
  outputs reach the after hook unchanged where they get redacted at
  the source; `apply_patch` is explicitly listed as local despite
  its underscore so it isn't misclassified as an MCP tool and
  false-positive blocked. The adapter ships a ~70-line TypeScript
  plugin embedded via `go:embed`; OpenCode auto-discovers it from
  `~/.config/opencode/plugins/` and Bun transpiles it natively (no
  jiti, no build step). No npm package. Verified against
  `@opencode-ai/plugin@1.15.13`, re-verified against `1.17.13`
  before this tag — hook signatures and MCP naming unchanged.
  `ctxcop install --harness=opencode` writes the plugin file; the
  autodetect probe also picks up `opencode` when
  `~/.config/opencode/` is present.

### Changed
- **README restructure + `docs/` split** (`cbe3d93`). README trimmed
  434 → 155 lines, leading with an agent-tool-call example and the
  install / wire / verify / uninstall flow; deep reference material
  moved to dedicated files: `docs/harnesses.md` (per-harness coverage +
  steering), `docs/detection.md` (rules, overlays, fixtures, project
  config), `docs/hook-contracts.md` (JSON wire shapes per harness /
  event), `docs/architecture.md` (code structure + invariants), and
  `docs/known-limits.md` (documented bypasses). Tone pass to declarative
  voice across all docs. Behavior unchanged.
- **Docs refresh for the Pi adapter and open-source tone**. README,
  `docs/harnesses.md`, `docs/hook-contracts.md`, `docs/architecture.md`,
  `docs/known-limits.md`, `ROADMAP.md`, `THREATMODEL.md`, `SECURITY.md`,
  `testing/README.md`, `internal/harness/iface.go`, and `CONTRIBUTING.md`
  updated to (a) name Pi everywhere the three-harness enumeration was
  stale and (b) drop residual internal-launch phrasing in favor of
  maintainer-voice. Behavior unchanged. New entries in
  `docs/known-limits.md` document the Pi-version-pinning fail-open and
  the Pi in-process memory window between tool exec and the
  `before_provider_request` redact pass.
- **Dependency bumps**. `github.com/spf13/viper` v1.19.0 → v1.21.0
  (`bf5e462`; pulls in `go-viper/mapstructure/v2` v2.4.0 as an indirect
  dep). `github/codeql-action` 4.35.5 → 4.36.0 (`0f33909`; `codeql.yml`
  + `scorecard.yml`).

### Fixed
- **Claude Code Elicitation / ElicitationResult hook input schema**
  (closes [#5](https://github.com/webflow/ctxcop/issues/5)). The struct
  tags expected `server_name` and `tool_name`; Claude Code 2.1.x
  actually sends `mcp_server_name` and no `tool_name` at all. Both
  fields silently unmarshaled to empty strings, so the
  `systemMessage` notice rendered `MCP server ""` and the audit log
  recorded `field: "/:api_key"` (slash + colon between empty strings).
  Detection itself was unaffected (`action` and `content` keys were
  correct), but the operator-facing surface was degraded for the
  whole v0.2.0 line. Drift originally captured in
  `testing/elicit-mcp/`'s stdin-tee experiment during the [#3]
  verification.
- **URL-mode elicitation recognized as the safe path** (same change).
  Draft spec 2025-11-25 introduces `mode: "url"` — out-of-band
  credential capture that doesn't enter the MCP transport or LLM
  context. ElicitationResult now passthroughs unconditionally on
  URL-mode rather than emitting the form-mode "consider migrating to
  URL-mode" notice (which was backwards when the user was already on
  URL-mode).
- **Empty-quote artifact in the notice surface** (same change). The
  systemMessage now renders `MCP server "acme"` or the generic
  `the MCP server` fallback, never `MCP server ""`. Regression
  asserted by `TestElicitationResultNoticeNeverContainsEmptyQuotes`
  and `TestElicitationResultHandlesMissingServerName`.

## [0.2.0] — 2026-05-21

The 0.2.0 line is the multi-harness release: ctxcop is no longer a Claude
Code-only tool. Codex CLI and Cursor adapters land alongside the existing
Claude Code coverage, with symmetric `install`/`uninstall` flows and a
shared skip-list / JSON walker / pause sentinel across all three. The
release also lands the supply-chain and governance scaffolding required to
take the repository public (Phases 1–3 of the OSS-readiness pass) and the
pure-OIDC release pipeline that produced this artifact.

### Security
- **Close ANSI-interleaved-secret bypass in splice** (`a149f92`). A secret
  with an ANSI escape between its bytes was detected on the stripped
  buffer but never spliced back into the original — the audit log and the
  `[ctxcop] redacted N secret(s)` stderr hint both claimed a redaction
  that hadn't happened. `RedactWithMatches` now falls back to splicing the
  stripped buffer for the whole content when any surface finding's bytes
  aren't contiguously present in the original. Regression coverage across
  four split positions in `internal/redact/ansi_test.go`.
- **Honor `ctxcop pause` across every harness handler** (`b90aa9f`).
  Previously only Claude Code's `PreToolUse` consulted the pause sentinel;
  Codex, Cursor, and Claude Code's `PostToolUse`/`UserPromptSubmit`/
  `Pre+PostCompact`/`ElicitationResult` kept making decisions while users
  thought ctxcop was off. `IsPaused()` and `Remaining()` lifted into
  `internal/pause` and consulted as the first check in every
  decision-producing hook.
- **Scan plain-text `tool_response` on JSON parse failure** (`0e23691`).
  Claude Code `PostToolUse` previously passed through silently when
  `tool_response` wasn't valid JSON; plain-text returns bypassed the
  scanner. Now falls back to scanning the raw bytes as a string (parity
  with Codex's existing behavior).
- **Cursor Read gated via `preToolUse` temp-file redirect** (`6c6c536`).
  Cursor's `postToolUse`/`updated_mcp_tool_output` is empirically only
  consumed by MCP-prefixed tools; built-in Read responses bypassed the
  override. Read intervention shifted to `preToolUse` with a redacted
  temp-copy redirect.

### Added
- **Codex CLI adapter** (`f9c36b9`) with autodetect-install and
  `--harness` flag.
- **Cursor adapter** (`b2c7ac1`) — `preToolUse`, `postToolUse`,
  `beforeSubmitPrompt`, `sessionStart`.
- **`ctxcop uninstall`** (`831d305`) with symmetric removal across all
  harnesses.
- **`--harness` flag** on `install`/`uninstall` for explicit targeting
  alongside the autodetect default.
- **Confirm-before-write prompt** (`00e3c6c`) for autodetect
  `ctxcop install` / `ctxcop uninstall`. Lists which harnesses + paths
  will be modified; non-TTY without `--yes` refuses to write
  (fail-closed default).
- **PreCompact, PostCompact, Elicitation, ElicitationResult hooks**
  (`82216d5`).
- **`--version` / `version` / `-v` subcommand** (`82216d5`) —
  linker-injected `version` string falling back to `debug.ReadBuildInfo`.
- **Paused-state notices** (`1d71c7a`). `pause.Banner()` surfaces a
  one-line "ctxcop is PAUSED" notice via `SessionStart` (once per session)
  and `UserPromptSubmit`/`beforeSubmitPrompt` (once per user turn) so a
  forgotten pause is obvious without spamming per-tool-call output.
- **OSS-readiness documentation** (`d14ce13`) ahead of the public flip:
  `SECURITY.md`, `THREATMODEL.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`,
  `CHANGELOG.md`, `THIRD_PARTY_AUDIT.md`, `ROADMAP.md`.
- **Governance + supply-chain scaffolding** (`d14ce13`):
  `.github/CODEOWNERS`, issue + PR templates, `ACTION_PIN_POLICY.md`,
  `.github/action-allowlist.txt`, `.github/dependabot.yml`.
- **CI workflows** (`6e1052b`, `296751e`): `ci.yml` (lint + test matrix),
  `codeql.yml`, `scorecard.yml`, `vuln-scan.yml` (govulncheck).
- **Vendored-dep import-allowlist check** (`6e1052b`) — fails the build
  if `vendor/github.com/betterleaks/betterleaks/{detect,config,report}/**`
  imports `os/exec`, `net/http`, `unsafe`, or `reflect`. Audit
  mitigation; regressions on those imports are a strong signal worth
  blocking on.
- **Pure-OIDC release pipeline** (`7b1b828`). `.github/workflows/release.yml`
  fires on `v*` tag push and produces, for the linux+darwin × amd64+arm64
  matrix: reproducible builds (`CGO_ENABLED=0 -trimpath`, `SOURCE_DATE_EPOCH`
  from the tag commit timestamp, pinned Go via `go-version-file: go.mod`),
  CycloneDX + SPDX SBOMs via syft, cosign keyless sign-blob via Sigstore
  Fulcio + Rekor, SLSA build-provenance attestations,
  `release-manifest.json` for tap-side pollers. Zero stored credentials
  — every cross-repo write removed.
- **Release tag-verify gate** (`7b1b828`, `2180af2`). The release
  workflow refuses lightweight or unsigned tags; the signer must be
  listed in `.github/release-allowed-signers` (CODEOWNERS-gated,
  security-team-reviewed PRs only).
- **betterleaks-SHA verification step** (`7b1b828`). Refuses to sign a
  release if `go.sum`'s betterleaks SHA drifts from the audited SHA in
  `THIRD_PARTY_AUDIT.md` without a matching review-log update. Audit
  mitigation #7.
- **Inverted-pull tap design** (`docs/tap-pull-poller.md`, `7b1b828`).
  Full design + ready-to-drop workflow YAML for the public homebrew tap
  repo. The tap polls source releases, cosign-verifies every artifact
  against the documented workflow identity, then opens a same-repo bump
  PR using only its own `GITHUB_TOKEN`. No cross-repo credential lives
  anywhere in either workflow.

### Changed
- **Harness directory layout** (`202f219`). `internal/{hook,install}` →
  `internal/harness/claudecode` to make room for sibling adapters; the
  hook-binary entrypoint and install logic for each harness live under
  `internal/harness/<name>/`.
- **Shared JSON walker** (`8310684`). Five copies of the
  `scanStrings`/`findRuleHits`/`redactStrings` recursion across the harness
  adapters consolidated into `internal/redact` (`FirstHit`, `AllHits`,
  `RedactTree`). `MaxWalkDepth=64` cap added to bound adversarial-MCP
  input cost.
- **Shared skip-list across harnesses** (`22be61c`). Cursor's
  `redirectIfReadHasSecret` and `denyIfWriteHasSecret` previously ignored
  the skip-list, so intentional fixture files got redirected/blocked.
  Extracted into `internal/skiplist`; both Cursor handlers now consult it.
- **README v0.2.0 pass** (`2bf5de1`) — multi-harness coverage,
  install/uninstall flows, hook output contracts.
- **Cursor agent-loop bypass documented** (`fcd6ea6`) — short user prompts
  triggering Cursor's agent-loop can surface file content without firing
  `preToolUse`. Empirically surfaced during rc.4 dogfooding; documented in
  `internal/harness/cursor/sessionstart.go`.
- **Branch protection** migrated from classic to a GitHub Ruleset;
  `required_signatures` rule added once local commit signing was
  configured.
- **Go directive bumped** `1.26.2` → `1.26.3` (`0339ffc`).
- **`govulncheck` bumped** `v1.1.5` → `v1.3.0` (`672b9cc`).

### Removed
- **Standalone gosec workflow** (`d2a43cc`) — already covered by
  golangci-lint's `gosec` linter; the second runner was duplicate noise.
- **Accidentally-committed test fixture file** (`2b1a9f0`).

## [0.1.2] — 2026-05-09

### Added
- **`ctxcop-bearer-token` rule** with canonical fixture coverage in
  `internal/redact/canonical_test.go`.

### Changed
- **MIT LICENSE** at repo root, **NOTICES.md** for third-party attribution.

## [0.1.1] — 2026-05-08

### Fixed
- **`UserPromptSubmit` JSON shape** — emit correct top-level
  `decision`/`reason` rather than nested `hookSpecificOutput` shape.
  Wrong-shape failures are silent successes, which is the worst class
  for a security control.

### Added
- **Hook output contracts** documented in the README so future harness
  adapters and contributors have a single reference.

## [0.1.0] — 2026-05-07

### Added
- Initial release: ctxcop wraps Claude Code's hook interface to redact
  credentials from tool output before they reach the model's context
  window. Subcommands: `scan`, `run`, `hook pre-tool-use`,
  `hook session-start`, `install`, `rules list`, `pause`, `resume`,
  `status`. Detection ruleset composed from betterleaks defaults + an
  embedded ctxcop pack + user TOML overlays + project `.ctxcop.toml`.

[Unreleased]: https://github.com/webflow/ctxcop/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/webflow/ctxcop/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/webflow/ctxcop/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/webflow/ctxcop/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/webflow/ctxcop/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/webflow/ctxcop/releases/tag/v0.1.0
