# Hook output contracts

Each harness has its own JSON output shapes per event. Mixing them up
tends to fail silently — the handler emits a plausible-looking response,
the harness doesn't recognize the field names for that event, and the
hook behaves as if it had returned passthrough. For a security control
this is the worst possible failure mode. The tables below are the source
of truth ctxcop's handlers use; the per-harness docs
([Claude Code](https://code.claude.com/docs/en/hooks.md),
[Codex](https://developers.openai.com/codex/hooks),
[Cursor](https://cursor.com/docs/hooks),
[Pi](https://pi.dev/docs/latest/extensions),
[OpenCode](https://opencode.ai/docs/plugins)) are authoritative.

## Claude Code

| Event | Block shape | Mutate shape | Notes |
| --- | --- | --- | --- |
| `PreToolUse` | `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"…"}}` | `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","updatedInput":{…}}}` | Can rewrite `tool_input`. |
| `PostToolUse` | n/a (can't block effectively post-hoc) | `{"hookSpecificOutput":{"hookEventName":"PostToolUse","updatedToolOutput":{…}}}` replaces `tool_response` (added in Claude Code 2.1.x; docs at [code.claude.com/docs/en/hooks](https://code.claude.com/docs/en/hooks) — was previously immutable, ctxcop's older releases treated it as such). | ctxcop emits `updatedToolOutput` (redacted copy) alongside `additionalContext` (soft notice, for clients/tools the rewrite doesn't reach). Spot-verified end-to-end against a live session 2026-08-03 — fixture + A/B in [testing/posttooluse-mcp](../testing/posttooluse-mcp/README.md). |
| **`UserPromptSubmit`** | **`{"decision":"block","reason":"…"}` (top-level, NOT nested under `hookSpecificOutput`)** | Cannot rewrite the prompt. Can emit `additionalContext`. | The shape difference from PreToolUse is easy to miss; regression test `TestUserPromptBlocksOnSecret` asserts the response is top-level AND not nested. |
| `SessionStart` | n/a | n/a | `{"hookSpecificOutput":{"hookEventName":"SessionStart","additionalContext":"…"}}` to prime the model. |
| `SessionEnd` | n/a | n/a | Side-effect-only (used for temp-file cleanup). |
| **`PreCompact`** | **`{"decision":"block","reason":"…"}` (top-level, like UserPromptSubmit — NOT nested)** | Cannot modify the compaction. Can emit top-level `{"systemMessage":"…"}` for soft warnings. | Same shape gotcha as UserPromptSubmit. ctxcop scans `transcript_path` for apparent secrets and emits a `systemMessage` (no block) — compaction is too disruptive to interrupt. |
| `PostCompact` | n/a (no `decision` field per spec) | n/a (compacted summary already in context) | Can emit top-level `{"systemMessage":"…"}` only — exit code is ignored. ctxcop scans the post-compaction transcript and warns if credential-shaped text appeared in the summary. |
| `Elicitation` | `{"hookSpecificOutput":{"hookEventName":"Elicitation","action":"decline"}}` | `{"hookSpecificOutput":{"hookEventName":"Elicitation","action":"accept","content":{…}}}` to pre-fill | ctxcop observes only — `content` is the user-typed answer and reaches the chokepoint via `ElicitationResult`, not here. |
| **`ElicitationResult`** | `{"hookSpecificOutput":{"hookEventName":"ElicitationResult","action":"decline"}}` (available but ctxcop doesn't currently use it) | `{"hookSpecificOutput":{"hookEventName":"ElicitationResult","action":"accept","content":{…}}}` could override answers (ctxcop doesn't currently mutate) | Observe-only: ctxcop scans `content` and emits a top-level `systemMessage` pointing at the [MCP spec](https://modelcontextprotocol.io/specification/2025-06-18/client/elicitation) when credential-shaped values appear (the spec forbids that in form mode). |

## Codex CLI

| Event | Block shape | Mutate shape | Notes |
| --- | --- | --- | --- |
| `PreToolUse` | `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"…"}}` | n/a — `updatedInput` is parsed but rejected at runtime ([openai/codex#18491](https://github.com/openai/codex/issues/18491)) | Deny-only on Codex PreToolUse. |
| `PostToolUse` | **`{"decision":"block","reason":"…"}` (top-level)** | n/a — `updatedMCPToolOutput` is "parsed but not supported yet" (fails open) | Top-level block + reason. Emitting `updatedMCPToolOutput` would silently leak. |
| `UserPromptSubmit` | `{"decision":"block","reason":"…"}` (top-level) | Cannot rewrite | Same shape as Claude Code. Codex parses both top-level and nested. |
| `SessionStart` | n/a | n/a | `{"hookSpecificOutput":{"hookEventName":"SessionStart","additionalContext":"…"}}`. |

## Cursor

| Event | Block shape | Mutate shape | Notes |
| --- | --- | --- | --- |
| `preToolUse` | `{"permission":"deny","user_message":"…"}` (flat, top-level — NOT nested under hookSpecificOutput) | `{"permission":"allow","updated_input":{…}}` | Cursor parses Claude-Code-compat nested too, but flat is preferred. Redirects `Read` to a redacted temp file via `updated_input`. |
| `postToolUse` | n/a | `{"updated_mcp_tool_output":{…}}` (snake_case body field despite camelCase event name) | Reliably honored only for MCP-prefixed tools. Built-ins (Shell/Write/Read response) bypass the override — compensate at preToolUse. |
| `beforeSubmitPrompt` | `{"continue":false,"user_message":"…"}` (flat) | Cannot rewrite | Use `user_message` (works) not `additional_context` (parsed but not surfaced — forum 155689, open). |
| `sessionStart` | n/a | `{"additional_context":"…"}` | Same not-surfaced bug as postToolUse — emitted for forward-compat but ctxcop's security guarantees don't depend on it. |

## Pi (pi.dev)

Pi's extension model is in-process TypeScript, not subprocess JSON-on-
stdin. The shapes below are what ctxcop's embedded bridge
(`internal/harness/pi/extension/ctxcop.ts`) returns to Pi; the bridge
shells out to `ctxcop hook pi <event>` and forwards the decision.

| Event | Block / mutate shape | Notes |
| --- | --- | --- |
| `before_provider_request` | Return the (possibly mutated) payload as the handler's return value. Pi replaces `currentPayload` with whatever the handler returns. | The load-bearing chokepoint. ctxcop recursively walks the provider HTTP body (Anthropic Messages, OpenAI chat, etc.) and returns the same tree with credential-shape strings replaced by `<REDACTED:…>`. Returning `undefined` means "no opinion; keep the payload". |
| `before_agent_start` | Return `{systemPrompt: "<accumulated + appended>"}` to append; `undefined` to leave unchanged. | One-time priming injection. Bridge gates with a closure-scoped boolean so only the first turn of a session pays the token cost. Subsequent calls return `undefined`. |
| `tool_call` | Return `{block: true, reason: "…"}` to refuse; `undefined` (or omit) to allow. | ctxcop only acts on MCP-prefixed tools (`mcp__*`) — built-in `bash`/`read`/`write`/`edit` are passthrough because their outputs reach the next `before_provider_request` and get redacted there. |
| `tool_result`, `input`, `session_before_compact`, `session_compact` | — not handled by ctxcop — | Subsumed by `before_provider_request`: every path that puts data in the model's context routes through there before send. The minimal-event surface is intentional. |
| `session_start` | `ctx.ui.notify(message, "info")` (cosmetic). | Not a chokepoint — just surfaces a "ctxcop active" notice to the user when running with a UI. |

## OpenCode (sst/opencode)

OpenCode's extension model is in-process TypeScript/JavaScript plugins
loaded by Bun. The shapes below are what ctxcop's embedded bridge
(`internal/harness/opencode/extension/ctxcop.ts`) returns to OpenCode;
the bridge shells out to `ctxcop hook opencode <event>` and applies
the decision. The plugin's `Hooks` interface passes `(input, output)`
where `output` is a reference — handlers mutate `output` in place
rather than returning a new value.

| Event | Block / mutate shape | Notes |
| --- | --- | --- |
| `tool.execute.before` | Block by `throw new Error(reason)` — propagates as a tool error to the model. Mutate by editing `output.args` in place (the bridge replaces every own enumerable key). | ctxcop only acts on exfil-class tools (`webfetch` + MCP tools with underscore-named conventions). Local tools (`bash`, `read`, `write`, `edit`, `grep`, `glob`, `ls`, `task`, `todowrite`) passthrough — their output is redacted on the after hook. |
| `tool.execute.after` | Mutate `output.output` (always a string) in place. No block path documented. | The catch-all redact pass. Splices `<REDACTED:…>` placeholders for credential hits across every tool's output, including MCP tool results. |
| `chat.params` | Not handled by ctxcop | Exposes sampling parameters (model, temperature, etc.) but not the assembled HTTP body, so it's not a redaction chokepoint. |
| `session.*`, `auth.*` and 20+ other lifecycle events | Not handled by ctxcop | Out of the credential-flow path. |

## Aider (Aider-AI/aider)

Aider has no hooks and no wire contract to document. The adapter is a
static-configuration integration — see
[docs/harnesses.md#aider](harnesses.md#aider) for the interposition
points (`lint-cmd`/`test-cmd` wraps and the `read:` priming file) and
the exact `.aider.conf.yml` transformations at install time.

The single `ctxcop hook aider preflight` subcommand takes no JSON
payload — it reads `.env` from the project root (or `--project-root
<path>`) and emits human-readable warnings to stderr. Not a wire
contract; it's a CLI utility the user invokes from a shell alias.

## Adding a new event handler

Write a test that asserts the exact key names of the output JSON, not
just "some response was produced". A handler that returns a
syntactically valid response of the wrong shape passes naive tests but
fails the security guarantee. Real incidents this pattern has caught:

- Claude Code `UserPromptSubmit` shape bug (top-level vs nested), fixed
  in commit `1adab3e`.
- Codex `PostToolUse` `updatedMCPToolOutput` non-support, surfaced in
  the original Chunk C draft.
- Cursor `Read` agent-loop bypass, surfaced during v0.2.0-rc.3
  dogfooding.

Harness docs and harness behavior drift, and silently. Test the wire
shape, not just the intent.
