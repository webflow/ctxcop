# Roadmap

This is a living document. Items move from "Backlog" to "In progress" to
"Done"; items move *off* the roadmap when they ship and into the
`CHANGELOG.md` as released features. Dates here are targets, not
commitments — a security tool's roadmap bends to whatever
vulnerability or upstream-bug surface area demands attention.

The roadmap is organized into four streams. Items inside each stream
are listed in rough priority order.

## Stream 1: Detection coverage

The detection layer's value is bounded by the credential formats it
recognizes. We grow this surface conservatively (single-purpose,
high-confidence rules) and depend on user/project overlays for the
long tail.

### Backlog

- **Codex streaming-shell variants** — Codex's `unified_exec`,
  `local_shell`, and streaming-shell payload shapes bypass our
  `PreToolUse` hook today. Upstream behavior tracked at
  github.com/openai/codex#18491. We can't gate egress through those
  paths until either upstream lands the hook contract change, or we
  add a shell wrapper that interposes before Codex.
- **Cursor WebSearch and AskQuestion coverage** — Cursor forum threads
  160761 and 152230 track the upstream gap. No on-ctxcop work to do
  until Cursor lands hook coverage for these tools; we'll then add
  scanners.
- **Anthropic API key rule audit** — the embedded rule depends on an
  `AA` literal suffix per the upstream regex. Verify that's still
  current as Anthropic's key format evolves; bump the rule if not.
- **Custom-prefix detection convention** — document the recommended
  shape for organizations defining their own
  `internal-prefix-<service>` rules so users don't accidentally write
  noisy regexes.

## Stream 2: Trust and verification

These items make ctxcop's claims user-testable rather than just
asserted.

### Backlog

- **Out-of-band ownership proof** — DNS TXT record on `webflow.com`
  listing the canonical release-signing identity
  (`webflow/ctxcop/.github/workflows/release.yml`), defeating
  typosquat confusion.
- **SLSA Build Level 3 graduation** — Phase 3 of the OSS launch
  lands SLSA L2 via the official reusable workflow's basic flow.
  L3 is the next step: enforces the full provenance chain including
  hermetic isolation between source-checkout and build steps.

- **Vendored-dep import-allowlist CI check** — fail the build if
  `vendor/github.com/betterleaks/betterleaks/{detect,config,report}/**`
  ever imports `os/exec`, `net/http`, `unsafe`, or `reflect`. The
  v1.2.0 audit verified those imports are absent today; a regression
  is a strong signal worth blocking on. Lands as part of Phase 2's
  `ci.yml` once we vendor the dep at release time. Tracking-only
  here — implementation is short (a `go list -deps -json` over the
  package list + JSON diff against an allowlist file).

## Stream 3: Harness coverage

ctxcop currently integrates with Claude Code, Codex CLI, Cursor,
Pi (pi.dev), OpenCode (sst/opencode), and Aider (static-config
integration; see [docs/harnesses.md#aider](docs/harnesses.md#aider)
for the narrower coverage). Each adapter is a self-contained subpackage
under `internal/harness/<name>/`.

### Backlog

- **Continue.dev integration** — extension-based AI agent; needs an
  in-process bridge like the Pi adapter under `internal/harness/pi/`,
  since there's no external-binary hook lifecycle.
- **OpenAI's official ChatGPT desktop app (when/if it ships a hook
  interface)** — wait for upstream contract before designing.
- **Claude Code `SubagentStart` as the subagent-priming chokepoint** —
  Claude Code's hook lifecycle grew a dedicated `SubagentStart` event
  (carrying `agent_id`/`agent_type`) since ctxcop's adapter was
  written. ctxcop currently primes subagents by prepending text to the
  `Agent`/`Task` tool's `PreToolUse` input — a workaround for the gap
  that `SessionStart` doesn't fire for derived sessions.
  `SubagentStart` looks like a cleaner purpose-built replacement, but
  swapping it in is a real behavior change (different trigger timing,
  different payload) — verify empirically before cutting over, don't
  just swap on docs.
- **Codex CLI: re-verify `PreToolUse` `updatedInput` support** —
  github.com/openai/codex#18491 (filed 2026-04-18, still open) says
  `updatedInput` is rejected at runtime; current Codex hooks docs
  (developers.openai.com/codex/hooks) say it's now supported for
  `Bash`/`apply_patch`. Those two sources disagree. ctxcop's adapter
  still denies credential-bearing input outright rather than rewriting
  it — don't change that until someone confirms which is actually true
  against a live Codex session.
- **Codex CLI: `PreCompact`/`PostCompact` coverage** — Codex's hook
  lifecycle added these (paralleling Claude Code's existing
  `PreCompact`/`PostCompact` handlers) since ctxcop's Codex adapter was
  written. Currently unwired; would close the same compaction-leak gap
  Claude Code already covers.
- **OpenCode `experimental.chat.messages.transform`** — a new hook
  exposing the full message history for mutation, closer to a
  `before_provider_request`-style payload-level chokepoint than the
  current tool-seam approach. `experimental`-prefixed (unstable API);
  revisit once/if it stabilizes.
- **Aider: LiteLLM callback interposition** — Aider uses LiteLLM under
  the hood and LiteLLM supports `success_callback`/`failure_callback`,
  but Aider exposes no userland knob to register one. If upstream ever
  surfaces a callback config, wire ctxcop's redactor as a LiteLLM
  callback for a payload-level chokepoint like Pi's
  `before_provider_request`. Blocked upstream; not actionable today.
- **Aider community fork (`dwash96/aider-ce`) adapter** — the fork
  carries the closed hooks PR forward
  ([Aider-AI/aider#4485](https://github.com/Aider-AI/aider/pull/4485))
  and does expose Claude-Code-style lifecycle events. A dedicated
  adapter targeting the fork would give full-hook coverage for users
  who've moved off mainline Aider. Gate on the fork gaining enough
  adoption to warrant a separate subpackage — today the mainline
  static-config adapter covers the population that matters.

## Stream 4: Operations and UX

Small quality-of-life items that compound over time.

### Backlog

- **Status-line integration** — emit a one-character status hint that
  shell prompts can pick up (active / paused / pause-expiring-soon)
  so users don't have to run `ctxcop status` to remember.
- **Compaction-summary detection improvements** — currently
  `PostCompact` warns on credential-shape findings in summaries. A
  more useful behavior would be to surface the specific re-synthesized
  pattern so the user knows what to look for. Requires storing the
  pre-compact transcript hash to diff against.
- **Pre-built artifact for Windows users** — currently `go install`
  works but there is no pre-built Windows binary. Document a supported
  install path once the release pipeline emits Windows artifacts.

## How to propose a roadmap addition

Open a GitHub issue with the label `roadmap`. Be specific about:

- The user-visible problem the item solves.
- Why it doesn't fit in a release-and-forget PR (i.e., why it's
  roadmap-scale).
- Rough acceptance criteria.

Maintainers triage roadmap proposals at a regular cadence and add
accepted items to the appropriate stream above.
