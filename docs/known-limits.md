# Known limits

- **Multi-encoded credentials.** zip+base64 wrapping and similar pass
  through past the depth limit. The detector recursively decodes up to
  depth 8; pathological onion-encodings beyond that are out of scope.
- **PostToolUse redaction depends on the client honoring
  `updatedToolOutput`.** Claude Code 2.1.x added that field to the
  PostToolUse hook (it used to forbid mutating `tool_response`
  entirely). ctxcop redacts via that field and pairs it with the older
  `additionalContext` notice as a fallback for clients or tools the
  rewrite doesn't reach. Verified end-to-end against a live session on
  2026-08-03 — see
  [testing/posttooluse-mcp](../testing/posttooluse-mcp/README.md) for
  the fixture and the A/B result. An older client that ignores the
  field falls back to the notice alone, in which case the literal is
  still visible and should be treated as unredacted.
- **Read line numbers may shift** when the original file contains a
  multi-line secret (PEM key) and the redacted copy collapses it.
  Single-line secrets preserve line numbers.
- **Subagent priming costs ~80 tokens per Agent invocation.** A
  predictable price for closing the SessionStart gap on derived
  sessions.
- **Cursor agent-loop file exploration bypasses hooks.** Verified
  empirically as of v0.2.0-rc.4: direct `Read` tool calls fire
  `preToolUse` and credential-bearing files get redirected to a
  redacted temp copy. But Cursor's agent-loop file reads ("Explored N
  files" + inline content, triggered by short prompts like "read
  test") surface file content WITHOUT firing `preToolUse`. Same class
  of gap as the documented WebSearch / AskQuestion bypass (forum
  160761 / 152230). No way to intercept from ctxcop's side. Workaround:
  phrase reads as explicit "read the file /abs/path" so Cursor uses
  the gated `Read` tool. If a credential-shape value surfaces from an
  "Explored" step, treat it as unredacted and rotate.
- **Codex `unified_exec` / `local_shell` / streaming-shell variants
  bypass hooks.** Only the standard `shell`-tool payload (single
  `command` string) fires Codex hooks today.
- **Cursor `updated_mcp_tool_output` is reliably honored only for
  MCP-prefixed tools.** Built-in tool responses (Shell, Write, Grep,
  etc.) flow to the model unmodified despite the PostToolUse override.
  Compensated by gating credential-bearing file reads pre-emptively in
  `preToolUse` via `updated_input` redirect.
- **Pi adapter is pinned to a specific Pi version.** The extension API
  shape (event names, payload schemas, in-process bridge mechanics)
  changes between Pi minor releases per their CHANGELOG. ctxcop's
  adapter is re-verified against `@earendil-works/pi-coding-agent`
  `0.80.3` (see [docs/harnesses.md](harnesses.md)); later Pi versions
  may need an adapter update before they're safe to use with ctxcop.
  Newer Pi with old ctxcop fails open (events the new Pi sends with
  new shapes simply don't match our struct tags and pass through
  unredacted) — the failure mode is "ctxcop sees nothing" rather
  than "ctxcop blocks everything".
- **Pi in-process memory window.** On Pi, a credential briefly exists
  in the Pi runtime's process memory between tool execution and the
  `before_provider_request` redact pass — the redaction happens just
  before the HTTP send, not at the source. A malicious co-resident
  extension could read it from memory in that window. ctxcop treats
  Pi's process boundary as part of its trust surface (same posture
  as the other harnesses' processes). If that boundary is suspect,
  audit your installed Pi extensions before relying on ctxcop.
- **OpenCode adapter is pinned to a specific plugin API version.**
  ctxcop is re-verified against `@opencode-ai/plugin@1.17.13` (see
  [docs/harnesses.md](harnesses.md)). The 1.x API has been stable
  since late 2025, but the `Hooks` interface gains additions between
  minor releases (the two ctxcop depends on —
  `tool.execute.before` / `tool.execute.after` — have not changed).
- **OpenCode `tool.execute.before` only blocks exfil-class tools.**
  By design, ctxcop only intervenes at the `before` hook for tools
  whose args cross the box boundary on call — `webfetch`, `websearch`,
  and MCP tools. Local tools (`bash`, `read`, `write`, `edit`,
  `apply_patch`, etc.) pass through; their outputs are redacted at
  `tool.execute.after` instead. The rationale matches Pi: blocking
  bash with a credential in `command` would break the legitimate
  `AWS_ACCESS_KEY_ID=AKIA…` patterns where the credential is meant to
  flow into the local shell and never reach the model.
- **OpenCode broken-plugin caching.** Bun caches failed module
  imports for the process lifetime — if the embedded `ctxcop.ts`
  fails to load (e.g., after a manual edit that introduces a syntax
  error), opencode will not retry until the user restarts the
  process. The successful-load log line is `"loading plugin"` at
  info level (`opencode --print-logs`).

## Aider

- **No `UserPromptSubmit`-equivalent.** Aider has no hook for chat
  input. A credential pasted into the chat prompt reaches the model's
  context and the transcript on disk unfiltered. The ctxcop priming
  file guides the model to steer users toward abstract references, but
  this is guidance, not enforcement.
- **Auto-detected linters bypass the wrap.** When `.aider.conf.yml`
  has no explicit `lint-cmd`, Aider infers per-language linters
  (`ruff` for Python, etc.) and invokes them directly. Those bypass
  the `ctxcop run --` wrap. Install-time warning surfaces this.
- **No LiteLLM callback interposition.** Aider uses LiteLLM under the
  hood, and LiteLLM does support `success_callback` / `failure_callback`
  hooks — but Aider does not expose a userland knob to register one.
  A payload-level chokepoint (like Pi's `before_provider_request`)
  would need Aider to surface that. Tracked in [ROADMAP.md](../ROADMAP.md).
- **LLM-emitted edit blocks bypass ctxcop.** If the model returns an
  edit block containing a literal secret, Aider's parser applies it
  to the local file directly — there is no `PreToolUse`-equivalent
  fire point. Downstream controls (a pre-commit `ctxcop scan` hook,
  or CI-side secret scanning) are the compensating layer.
- **Aider is in maintenance mode.** The project's maintainer has
  publicly noted maintenance-mode status (see
  [Aider-AI/aider#4485](https://github.com/Aider-AI/aider/pull/4485)
  closure comment). If ctxcop needs to react to an upstream schema
  change, expect the response cycle to be slow. Community fork
  [dwash96/aider-ce](https://github.com/dwash96/aider-ce) carries
  the closed handlers PR forward; a dedicated adapter targeting the
  fork is on the roadmap.

## Content layer, not network layer

ctxcop redacts secrets from tool I/O at the harness-hook boundary. It is
**not** a network egress proxy, firewall, or MCP gateway: it does not sit
on the connection path and does not block traffic by destination. Whole
classes of egress control are therefore out of scope by construction —
SSRF, DNS/hostname exfiltration, egress allow/blocklists, WebSocket and
agent-to-agent transports, MCP tool-definition poisoning, behavioral
multi-step tool-chains, obfuscated command-intent detection, and network
response MITM. ctxcop is complementary to a network egress proxy, not a
replacement for one. This boundary was measured against an external
corpus; see [agent-egress-bench.md](agent-egress-bench.md) for the
methodology, the content-DLP results, and a per-case breakdown of what is
covered vs. deliberately out of scope.
