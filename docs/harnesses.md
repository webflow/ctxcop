# Per-harness coverage

ctxcop integrates with six harnesses today. Claude Code has the deepest
coverage (it was the original target and ships the most hook events). Codex
CLI and Cursor cover what their hook lifecycles currently expose; Pi
exposes a single trust-boundary chokepoint (`before_provider_request`)
that lets a minimal three-event integration cover what takes 6+ events
elsewhere; OpenCode's plugin system gives us in-place args + output
mutation across every tool via a two-event surface. Aider is the outlier —
it has no hook system at all (upstream is in maintenance mode), so ctxcop
integrates via static configuration rather than runtime events, with
correspondingly narrower coverage. Feature parity is bounded upstream, not
by ctxcop's design.

Every block reason ends in a concrete `Retry with …` instruction so an
autonomous agent has somewhere to go after a denial. See
[Steering the agent](#steering-the-agent) at the bottom of this file.

## Claude Code

Installs nine hooks via `~/.claude/settings.json`.

### PreToolUse

Can mutate `tool_input` (via `updatedInput`) and deny the call (via
`permissionDecision: "deny"`). Dispatches per `tool_name`:

| Tool | Action | What it closes |
| --- | --- | --- |
| `Bash` | Rewrites `command` to `ctxcop run -- bash -c '<original>'`. The wrapper executes the child under a real shell, captures stdout/stderr, runs the redactor, and emits the redacted output back to the model. Shell builtins, multi-line scripts, pipelines, heredocs all keep their semantics. | Secrets emitted by any CLI tool the agent runs. |
| `Read` | Reads the file, redacts in memory, writes a 0600-mode copy under `$TMPDIR/ctxcop/<hash>_<basename>`, rewrites `file_path` to point at it. | `cat`-equivalent reads of `.env` files, credential files, kubeconfigs. |
| `Write` / `Edit` / `NotebookEdit` | Scans `content` / `new_string`. If a secret is present, denies with a `permissionDecisionReason` that names the field, names the rule, and lists three retry forms (env-var reference, template placeholder, `# gitleaks:allow` annotation). | The model trying to persist a literal credential it learned about. |
| `WebFetch` | Scans `url` and `prompt`. Denies on hit with guidance to switch to Bash + curl with an env-var auth header. | Outbound exfiltration of credentials in URLs or query parameters. |
| `mcp__*` | Recursive walk of every string field in `tool_input`. Denies on first hit; the `permissionDecisionReason` names the JSON path (`blocks[0].text`, `data.password`, …). | Forwarding credentials to third-party MCP server processes. |
| `Agent` / `Task` | Prepends the priming message to the subagent's `prompt`. | The subagent gap: SessionStart hooks don't fire for derived sessions. |

The Bash rewrite is transparent. Claude doesn't have to know `ctxcop`
exists, and no `CLAUDE.md` needs to teach the agent special incantations.

### PostToolUse

As of Claude Code 2.1.x, PostToolUse can mutate `tool_response` via
`hookSpecificOutput.updatedToolOutput` ("replaces the tool's result" —
[hooks reference](https://code.claude.com/docs/en/hooks)). Earlier
ctxcop releases treated PostToolUse as observe-only because the hook
contract used to forbid response mutation; that's no longer true, and
ctxcop now redacts in place instead of only warning.

For non-(Bash|Read) tool calls, ctxcop scans `tool_response`. On a hit
it emits both:

- `updatedToolOutput`: a deep copy of the response with every matched
  string spliced to a `<REDACTED:…>` placeholder — the model doesn't
  see the literal value if the client honors the rewrite.
- `additionalContext`: a notice that states what fired and where (e.g.
  `rule: aws-access-token at "data.access_token"`), explains the
  redaction, and gives handle-with-care + rotation guidance for the
  case where the literal value is still visible (older client, or a
  tool the rewrite doesn't apply to).

Verified end-to-end against a live session on 2026-08-03: an MCP tool
whose response carried a synthetic credential the model had no other
access to came back as a placeholder, and the same run with
`CTXCOP_POSTTOOLUSE=off` returned the literal. Fixture and full result in
[testing/posttooluse-mcp](../testing/posttooluse-mcp/README.md).

Two env knobs keep this signal useful instead of noisy:

- `CTXCOP_POSTTOOLUSE_ALLOW='mcp__vault__*,mcp__1password__*,*secret*'` —
  tools whose output is supposed to contain secrets. Their hits go to
  the audit log as `warned-suppressed`; no model-facing notice.
- `CTXCOP_POSTTOOLUSE=off` — disable the handler entirely.

### UserPromptSubmit

Fires before the prompt reaches the model. ctxcop denies prompts
containing apparent secrets with a reason that guides the user toward
an env-var pattern or an abstract reference. Closes a leak path no
tool-level hook can catch.

### SessionStart

Each new top-level session starts with a single `additionalContext`
block stating:

- ctxcop is active; tool output is auto-redacted; tool inputs with
  credentials are blocked.
- Reference secrets via `$ENV_VAR` in a shell command — substitution
  happens in the child shell, the value never enters the model's tokens.
- In code, emit `process.env.X` / `os.Getenv("X")` references, not
  literals.
- For HTTP auth, use Bash + curl with `Authorization: Bearer $TOKEN`.
- Project the field you need (`--query 'Arn'`) over the whole response.
- A `<REDACTED:…>` placeholder means the value never reached you — don't
  try to recover it via base64/xxd.

Roughly 80 tokens per session. The agent learns the canonical patterns
before it tries something that fires a denial.

Subagents don't trigger SessionStart in Claude Code, so the same priming
text is injected via the `Agent` / `Task` handler under PreToolUse.

### SessionEnd

Removes the redacted-copy temp files the Read interception created, and
prunes any >24h leftovers. Files only contain placeholders, but the file
paths leak which files the agent read; cleanup is hygiene.

### PreCompact / PostCompact

Read `transcript_path` and scan for credential-shape data. PreCompact
warns before compaction (the upcoming summary inherits whatever's in
the source); PostCompact catches credential-pattern text the
summarizer may have re-synthesized from earlier redacted content. Both
emit top-level `systemMessage` warnings — they cannot modify the
compaction itself.

### Elicitation / ElicitationResult

For MCP elicitation forms (the structured-input path). Elicitation is
observe-only. ElicitationResult scans the user's submitted `content`
for credential-shape data and emits a top-level `systemMessage`
pointing at the [MCP specification](https://modelcontextprotocol.io/specification/2025-06-18/client/elicitation),
which explicitly forbids form-mode elicitations from carrying
credentials. Observe-only by design — does not modify the submission.
URL-mode elicitation (the spec's safe path for credential capture)
is passthrough.

## Codex CLI

Hook lifecycle: `PreToolUse`, `PostToolUse`, `UserPromptSubmit`,
`SessionStart`. Two material differences from Claude Code:

1. **`PreToolUse` cannot transparently rewrite commands.** Codex's
   `updatedInput` field is in the schema but rejected at runtime
   ([openai/codex#18491](https://github.com/openai/codex/issues/18491)).
   ctxcop denies credential-bearing inputs with `permissionDecision: "deny"`
   plus a `permissionDecisionReason` that pushes the engineer to
   reference $ENV_VAR before invocation.

2. **`PostToolUse` blocks the response with a reason, not in-place
   redaction.** Codex documents
   `hookSpecificOutput.updatedMCPToolOutput` for response mutation but
   flags it "parsed but not supported yet" (fails open). Emitting it
   would silently leak the credential while making ctxcop's audit log
   claim a successful redaction. ctxcop uses the working path: top-level
   `decision: "block"` + `reason` that names the rule + field, explains
   side effects already happened, and recommends rotation.

Caveats: hooks fire only for the standard shell-tool payload (single
`command` string). `unified_exec`, `local_shell`, and streaming shell
variants currently bypass ctxcop with no notification.

## Cursor

Hook lifecycle: `preToolUse`, `postToolUse`, `beforeSubmitPrompt`,
`sessionStart`. Differences:

1. **Flat output shape** (not nested under `hookSpecificOutput`):
   `preToolUse` emits `{permission, user_message, agent_message, updated_input}`;
   `postToolUse` emits `{updated_mcp_tool_output, additional_context}`;
   `beforeSubmitPrompt` emits `{continue, user_message}`. Cursor parses
   both flat and Claude-Code-compat-nested; flat is the documented
   preferred form.

2. **`updated_input` is honored on `Read`.** Same redirect pattern as
   Claude Code: read the file, scan it, redact in memory, write a temp
   copy under `$TMPDIR/ctxcop/`, return
   `{permission:"allow", updated_input:{file_path:"/tmp/..."}}`. Cursor
   reads the temp copy; the model sees placeholders. Verified
   empirically end-to-end in v0.2.0-rc.4.

3. **`updated_mcp_tool_output` is reliably consumed only by MCP-prefixed
   tools.** Documented as generic, empirically MCP-only. The Read
   redirect (above) is the compensating chokepoint for built-in file
   reads.

Tool names: `Shell` (not Bash), `Write` (covers Edit), `Read`, `Grep`,
`Delete`, `Task`. ctxcop dispatches on the `MCP:` prefix rather than
parsing out a `<server>`/`<tool>` substructure — Cursor's docs describe
the *matcher* syntax as `MCP:<tool_name>` (not confirmed to include a
server segment), but since ctxcop only checks the prefix, the exact
shape of what follows doesn't affect dispatch. ctxcop gates `Shell`,
`Write`, `Read`, and `MCP:*` in `preToolUse`; the rest pass through.

Upstream bugs (still open as of Cursor 3.8, June 2026 — see
[docs/known-limits.md](known-limits.md) and forum threads
[161911](https://forum.cursor.com/t/askquestion-tool-does-not-trigger-cursor-hooks-repost/161911)/
[161836](https://forum.cursor.com/t/cursor-cli-askquestion-tool-skips-pretooluse-and-posttooluse-hooks/161836)):
`WebSearch` and `AskQuestion` never trigger hooks; the agent-loop
"Explored N files" path can surface file content without firing
`preToolUse`; `additional_context` is parsed but not surfaced. ctxcop
uses `user_message` instead, which works.

## Pi (pi.dev)

Pi's extension model is structurally different from the other three:
extensions are TypeScript modules that Pi auto-discovers from
`~/.pi/agent/extensions/` (or `<cwd>/.pi/extensions/`) and loads
in-process via jiti. ctxcop ships a small bridge file (~50 lines of
TypeScript) that Pi transpiles at startup and embeds via `go:embed`
in the ctxcop binary. The bridge spawns `ctxcop hook pi <event>` per
event — same subprocess pattern as the other adapters, just with a
thin JS shim because Pi's runtime is in-process.

The integration uses three events rather than the larger set on
Claude Code, because Pi exposes a single chokepoint that covers what
multiple events cover elsewhere:

1. **`before_provider_request`** — fires with the fully-assembled LLM
   HTTP payload (provider-shaped: Anthropic Messages body, OpenAI
   chat body, etc.) immediately before send. ctxcop recursively walks
   the payload tree, redacts every credential-shaped string, and
   returns the mutated tree. Pi sends the mutation; the LLM provider
   never sees the literals. **This is the load-bearing chokepoint** —
   one pass at this layer covers system prompt, message history
   (including all prior tool results), the current user prompt, tool
   definitions, and any provider-specific fields. Compaction
   summaries, MCP server responses, re-synthesized credentials — all
   caught here automatically.

2. **`before_agent_start`** — fires once per user turn with the
   accumulated system prompt; ctxcop appends its canonical priming
   text (env-var patterns, REDACTED-placeholder semantics, MCP
   guidance). Gated by a closure-scoped boolean so the priming text
   is appended only on the first turn of the session.

3. **`tool_call`** — fires before every tool execution. ctxcop only
   acts on MCP tools (those whose name starts with `mcp__`) and
   blocks calls whose `input` contains credential-shape data. The
   block reason names the JSON path + rule and recommends configuring
   MCP server auth server-side. Built-in `bash`, `read`, `write`,
   `edit`, `grep` are passthrough — their outputs land in the
   `before_provider_request` payload and get redacted there.

Notably absent: `tool_result`, `input`, `session_before_compact`,
`session_compact`. Pi's `before_provider_request` fires before every
LLM call and walks the entire payload, so those events are already
covered at the trust boundary. The minimal-event surface keeps the
adapter simple and matches Pi's "extensions intercept what they care
about" design philosophy.

Tool names per Pi's `packages/coding-agent/src/core/tools/` upstream:
`bash` (input shape `{command, timeout?}`), `read` (`{path, offset?, limit?}`),
`write`, `edit`, `grep`, `find`, `ls`. Plus MCP tools prefixed with
`mcp__<server>__<tool>`. No `webfetch` — Pi expects bash+curl, which
plays into ctxcop's existing "reference via $ENV_VAR" guidance.

### Why no Bash wrap on Pi

Claude Code's adapter rewrites Bash `command` to
`ctxcop run -- bash -c '<orig>'` to intercept execution and redact
stdout/stderr in flight — originally because PostToolUse couldn't
mutate `tool_response` at all; that's since changed (see the Claude
Code PostToolUse section above), but the wrap stays: it works
identically across client versions and doesn't depend on the newer
`updatedToolOutput` field being honored. Pi's `before_provider_request`
lets us redact the *message* containing the tool result, post-execution,
on the way to
the LLM. No wrapping needed; the credential briefly exists in Pi's
process memory between tool exec and LLM send, but never crosses the
trust boundary unredacted.

### Pinned Pi version

Adapter re-verified against `@earendil-works/pi-coding-agent` `0.80.3`
(2026-06-30; previously verified against `0.75.4`). No breaking
changes to the `session_start` / `before_agent_start` / `tool_call` /
`before_provider_request` event shapes ctxcop's bridge depends on
between those releases — confirmed against Pi's CHANGELOG and
`docs/extensions.md`. `0.79.10` added richer `session_before_compact`
/ `session_compact` metadata (`reason`, `willRetry`) that ctxcop
doesn't currently consume; see ROADMAP for whether that's worth
wiring up.

There's no version literal to bump in code — the pin is this doc note.
Update it deliberately when re-verifying against a newer Pi release,
and re-run the local verification rig in `testing/` before merging.

## OpenCode (sst/opencode)

OpenCode's extension model is a plugin system: TypeScript or
JavaScript modules auto-discovered from `~/.config/opencode/plugins/`
(or `<cwd>/.opencode/plugins/`) and loaded in-process by Bun. ctxcop
ships a small bridge file (~70 lines of TypeScript) embedded via
`go:embed` in the ctxcop binary; `ctxcop install --harness=opencode`
writes it to the plugin directory. Bun transpiles `.ts` natively — no
jiti, no build step. The bridge spawns `ctxcop hook opencode <event>`
per event, same subprocess pattern as the other adapters.

Two events cover the whole tool surface:

1. **`tool.execute.before`** — fires before every tool execution with
   `(input, output)` where `output.args` is the tool's input args
   (passed by reference, mutated in place). ctxcop only acts on
   exfil-class tools — `webfetch`, `websearch`, and MCP tools (those
   whose name contains an underscore, per OpenCode's `<server>_<tool>`
   naming convention, *except* the explicitly-listed local tool
   `apply_patch`) — and *blocks* (by throwing) when their args contain
   credential-shape data. Local tools (`bash`, `read`, `write`,
   `edit`, `apply_patch`, `grep`, `glob`, `ls`, `task`, `todowrite`)
   passthrough at this stage; their output is handled below.

2. **`tool.execute.after`** — fires after every tool execution with
   `output.output` as a string (OpenCode stringifies all tool outputs
   before this hook). ctxcop scans the output, splices in
   `<REDACTED:…>` placeholders for credential hits, and mutates
   `output.output` in place. This is the catch-all that covers `bash`
   captures of secrets in env, `read` of `.env`-style files, MCP
   tool results, and anything else returning a credential-shape
   string.

Notably absent: a `before_provider_request`-style payload-level
chokepoint. OpenCode's `chat.params` event exposes sampling
parameters but not the assembled HTTP body, so we redact at the tool
seam instead. The trade-off is one extra subprocess invocation per
tool call (instead of one per LLM round-trip), in exchange for
redactions that happen at the source rather than just before send.

Tool names per OpenCode's built-in tool registry:
`bash` (`{command, description?}`), `read` (`{filePath, offset?, limit?}`),
`write` (`{filePath, content}`), `edit`, `apply_patch` (alternate local
edit path — explicitly listed as local despite its underscore, so the
MCP-naming heuristic below doesn't misclassify and false-positive block
it), `grep`, `glob`, `ls`, `webfetch`, `websearch` (added to the
registry after ctxcop's original pin; gated the same as `webfetch`
since it makes an outbound call with the query), plus MCP tools as
`<server>_<tool>`.

### Pinned OpenCode plugin version

Adapter re-verified against `@opencode-ai/plugin@1.17.13` (2026-07-01;
previously verified against `1.15.13`; `opencode-ai` and
`@opencode-ai/plugin` now version in lockstep). OpenCode's plugin API
has been stable across the 1.x line (since late 2025); the two hook
signatures ctxcop depends on (`tool.execute.before` /
`tool.execute.after`) are unchanged, confirmed against `dist/index.d.ts`.
MCP tool naming is still `<server>_<tool>` (underscore-joined),
confirmed against `packages/opencode/src/mcp/catalog.ts`.

Two things worth tracking, not yet acted on:

- **`experimental.chat.messages.transform`** — a new hook exposing the
  full message history for mutation, closer to a `before_provider_request`-
  style payload-level chokepoint than the tool-seam approach below.
  `experimental`-prefixed (unstable API) — a future option, not adopted
  yet.
- **`bash`'s tool ID is slated to change at OpenCode 2.0** per a source
  comment in `shell/id.ts` ("Rename with opencode 2.0") — watch for it;
  ctxcop's `localTools`/exfil dispatch matches on exact tool-name
  strings and would silently stop covering `bash` if the name changes
  underneath it.

There's no version literal to bump in code — the pin is this doc note.
Update it deliberately when re-verifying against a newer OpenCode
release.

## Aider

[Aider](https://aider.chat) ([Aider-AI/aider](https://github.com/Aider-AI/aider)) is the only harness ctxcop supports that has **no hook / lifecycle-
events surface at all**. The PR that would have added Claude-Code-style
hooks ([Aider-AI/aider#4485](https://github.com/Aider-AI/aider/pull/4485))
was closed unmerged with the maintainer commenting that Aider is in
maintenance mode; the corresponding feature request
([#5300](https://github.com/Aider-AI/aider/issues/5300)) was closed
2026-06-20. Aider also has no MCP surface, no sub-agent surface, and no
tool-call lifecycle: it's a chat-then-apply-edits loop where the LLM
returns edit blocks and Aider applies them locally.

ctxcop therefore integrates via static configuration in `.aider.conf.yml`
rather than runtime events. That gives narrower coverage than the
hook-based adapters, and the coverage delta is called out prominently
below and in [docs/known-limits.md](known-limits.md#aider).

### What ctxcop wires up at install time

Three interposition points that actually exist today:

1. **`lint-cmd` wrap**. Aider auto-runs `lint-cmd` after every edit and
   feeds the output back into the model's context so it can reason about
   failures. `ctxcop install --harness=aider` rewrites every `lint-cmd`
   entry to `<lang>:<ctxcop-path> run -- bash -c '<original-cmd>'` (or
   `<ctxcop-path> run -- bash -c '<original-cmd>'` for bare-command
   entries). Routing through `bash -c` rather than a bare prefix means
   the *entire* original command — compound commands joined with
   `&&`/`;`, env-var prefixes like `CI=1 pytest`, `cd`-prefixed
   commands — keeps its shell semantics and its combined output flows
   through ctxcop's redactor as one unit, not just the first shell
   word. The `<lang>:` prefix is preserved (no space required, matching
   Aider's own `^[a-z]+:` grammar) so Aider's per-language dispatch
   still works. Idempotent: re-running install detects the wrap and
   leaves it alone.
2. **`test-cmd` wrap**. Same shape as `lint-cmd`, but through
   `<ctxcop-path> run --stream -- bash -c '<original-cmd>'` (streaming
   because tests are long-running and Aider consumes output
   incrementally).
3. **`read:` priming**. ctxcop writes `~/.aider/ctxcop-priming.md`
   with a SessionStart-equivalent block (env-var conventions,
   `<REDACTED:…>` semantics, why not to try to reverse a placeholder)
   and adds that path to `.aider.conf.yml`'s `read:` list. Aider loads
   `read:` files as pinned context on every session, so every future
   `aider` invocation opens with the model having seen these
   conventions — no runtime hook needed to inject them.

### The preflight subcommand

Because Aider has no hook to fire it from, ctxcop ships a manual
`preflight` subcommand:

```sh
ctxcop hook aider preflight [--project-root <path>]
```

It scans the project's `.env` (Aider's default env-file location) for
credential-shape values and stderr-warns if it finds any. Aider loads
`.env` into its process environment, and a wrapped `lint-cmd` /
`test-cmd` that echoes an env var will still surface the literal — the
preflight is the defense.

The priming file suggests the user wire it into a shell alias:

```sh
alias aider='ctxcop hook aider preflight && aider'
```

We don't install the alias — the shell alias file is user territory —
but we document the pattern.

### What ctxcop does NOT cover on Aider

- **User prompts.** No `UserPromptSubmit`-equivalent exists in Aider.
  A credential pasted into chat reaches the model's context and the
  transcript on disk unfiltered. The priming file tells the model to
  guide the user toward abstract references, but this is guidance, not
  enforcement.
- **Auto-detected linters.** When the user omits `lint-cmd`, Aider
  falls back to per-language auto-detected linters (`ruff` for Python,
  `flake8`, etc.) invoked directly. Those bypass the wrap. Install
  emits a warning when it sees `.aider.conf.yml` with no `lint-cmd`
  configured.
- **LiteLLM round-trip.** Aider uses LiteLLM under the hood, and
  LiteLLM supports `success_callback` / `failure_callback` hooks — but
  Aider does not expose a way to register one from userland. A
  `before_provider_request`-style payload-level chokepoint like Pi's
  would need Aider to surface that knob or ship a formal callback API.
  See [ROADMAP.md](../ROADMAP.md).
- **Edit blocks the LLM returns.** These flow through Aider's parser
  into local file writes. If the LLM emits a literal secret in an edit
  block, ctxcop cannot intercept it — there's no `PreToolUse`-equivalent
  fire point. Downstream tooling (`ctxcop scan` piped through a git
  pre-commit hook, or a secret-scanner in CI) is the compensating
  control.

### Pinned Aider version

Adapter re-verified against Aider `v0.86.0` (last release before the
maintenance-mode transition; 2026-05-08). The `.aider.conf.yml` schema
keys ctxcop touches — `lint-cmd`, `test-cmd`, `read` — have been
stable since Aider `v0.30`. There's no reason to expect them to change
while upstream stays in maintenance mode, but if they do, this doc
note is the pin.

## Steering the agent

Detection-and-block alone strands an autonomous agent: it tried
something, got denied, and now needs to figure out what to do next.
Every block reason ends in a concrete `Retry with …` instruction:

- **Write/Edit block**: "Pick one of: `process.env.NAME`, a
  `<your-X>` template placeholder, or `# ctxcop:fixture` (or
  `gitleaks:allow`) on the same line for an intentional fixture. Retry
  with one of those forms."
- **WebFetch block**: "Switch to Bash and call curl with the credential
  from an env var: `curl -H \"Authorization: Bearer $TOKEN\" …`. Retry
  with curl-via-Bash or no credential."
- **MCP block**: "Configure the MCP server's auth server-side in
  `.mcp.json` (env block) instead of forwarding the user's. Retry with
  the credential removed from tool_input."
- **UserPromptSubmit block**: "Re-submit with the secret removed, an
  abstract reference, or loaded into a shell env var first."

After a Bash redaction, the wrapper appends a one-line hint to the same
`tool_result` the agent already received:

```
[ctxcop] redacted 2 secret(s) (ctxcop-aws-access-key, aws-access-token)
before this output reached the model. To USE the value in follow-up
work, reference it via $ENV_VAR in a shell command — substitution
happens in the child shell, so the value never enters your context.
Don't pipe through base64/xxd to reveal it: that's tracked in the
audit log and still bypasses your threat model.
```

Session-start priming, Agent/Task priming injection, and per-event
guidance together mean the agent doesn't have to re-derive the right
pattern each time.
