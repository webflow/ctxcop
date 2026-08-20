# Architecture

```
internal/
├── audit/       opt-in JSONL log writer; fails open on disk errors
├── harness/     one subpackage per AI agent harness; each implements its own
│   │           event handlers + Install/Uninstall + priming. All handlers
│   │           are fail-open by design.
│   ├── claudecode/   Claude Code (~/.claude/settings.json)
│   │                 PreToolUse, PostToolUse, UserPromptSubmit,
│   │                 SessionStart, SessionEnd, PreCompact, PostCompact,
│   │                 Elicitation, ElicitationResult (9 events)
│   ├── codex/        OpenAI Codex CLI (~/.codex/config.toml)
│   │                 PreToolUse (deny-only), PostToolUse (block-with-reason —
│   │                 updatedMCPToolOutput is parsed-but-unsupported on today's
│   │                 Codex), UserPromptSubmit, SessionStart
│   ├── cursor/       Cursor (~/.cursor/hooks.json)
│   │                 preToolUse (deny + redirect on Read),
│   │                 postToolUse (updated_mcp_tool_output),
│   │                 beforeSubmitPrompt, sessionStart
│   ├── pi/           Pi (~/.pi/agent/extensions/ctxcop.ts — embedded TS bridge,
│   │                 auto-discovered + jiti-transpiled in-process). 3 events:
│   │                 before_provider_request (load-bearing chokepoint —
│   │                 redacts the whole LLM HTTP payload), before_agent_start
│   │                 (priming), tool_call (MCP exfil block).
│   └── opencode/     OpenCode (~/.config/opencode/plugins/ctxcop.ts — embedded
│                     TS plugin, auto-loaded by Bun, no transpile step). 2
│                     events: tool.execute.before (block exfil-class tools
│                     with credential-shape args), tool.execute.after (redact
│                     output string for every tool).
├── redact/      ANSI strip + betterleaks library invocation + offset-safe splice
├── rules/       config composition (defaults + embedded + user + env)
├── runner/      fork/exec child for Bash rewrite; buffered & streaming variants
├── pause/       global pause/resume sentinel
└── skiplist/    shared skip-list (testdata, fixtures, *_test.*) for all harnesses

cmd/ctxcop/main.go  CLI dispatcher (per-harness routing, prompt UX,
                    autodetect-and-confirm install/uninstall)
```

Adding a new harness: create a sibling subpackage under
`internal/harness/`, implement event handlers + `Install`/`Uninstall`,
and add a top-level subcommand to `cmd/ctxcop/main.go` that routes to
them. Conventions are documented in `internal/harness/iface.go`.

## Invariants

- **Fail-open everywhere.** Every hook handler catches its own errors and
  returns an empty JSON object on failure, so a ctxcop bug cannot block
  a tool call. The rules loader recovers from `regexp.MustCompile`
  panics so a single bad rule (anywhere in the chain) falls back to
  upstream defaults.
- **No silent state.** Audit logging is off unless `CTXCOP_AUDIT_LOG` is
  set. Temp files from Read interception clean up at SessionEnd
  (Claude Code) and on TTL (other harnesses). The binary itself emits
  nothing to disk by default.
- **Recursion safety.** The Bash rewrite expands `command` to
  `ctxcop run -- bash -c '<orig>'`. The child shell runs outside the
  harness's tool envelope, so PreToolUse does not re-fire on the
  wrapped invocation. The `isAlreadyWrapped` check is a
  belt-and-suspenders guard. (Claude Code only — Codex doesn't support
  `updatedInput` at runtime today, and Cursor's gating is per-tool
  rather than via command rewriting.)
- **Idempotent install/uninstall.** Re-running `ctxcop install`
  recognizes prior entries (matched by `" hook <subcmd>"` substring,
  not by literal binary path) and replaces them in place; unrelated
  hooks and settings from other tools are preserved. `ctxcop uninstall`
  is the symmetric inverse.
- **Confirm-before-write by default.** Autodetect `ctxcop install` and
  `ctxcop uninstall` show the plan and prompt for y/N before mutating
  any file. `--yes` / `-y` skips for scripted use. Non-TTY stdin
  without `--yes` is treated as "no" — fail-closed default for a
  security tool.

## Implementation notes

The detector is cached per process. `internal/rules` exposes `Reset()`
for tests that need a fresh loader.

`internal/redact/splice.go` uses `strings.Replace` on `Finding.Match`
rather than gitleaks' `StartLine`/`StartColumn` coordinates. Those
coordinates are 0-indexed for line, 1-indexed for column, with a known
+1 off-by-one on lines past the first. `Match` is unambiguous and
UTF-8 safe.

ANSI escape sequences in tool output can split a credential across
bytes. The redactor strips ANSI to a side buffer, runs detection on the
stripped form, and splices placeholders back into the original. When
finding bytes aren't contiguously present in the original, the splicer
falls back to replacing the whole content with the stripped form.
Regression coverage in `internal/redact/ansi_test.go`.

The JSON walker (`internal/redact.FirstHit` / `AllHits` / `RedactTree`)
recursively descends `tool_input` / `tool_response` structures with a
`MaxWalkDepth=64` cap to bound adversarial-MCP input cost.
