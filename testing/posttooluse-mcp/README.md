# posttooluse-mcp — live-session test fixture

End-to-end test fixture for ctxcop's Claude Code `PostToolUse` redaction,
built for [#80](https://github.com/webflow/ctxcop/issues/80).

`PostToolUse` is the output-side chokepoint for every tool ctxcop does not
already cover at `PreToolUse`. It deliberately skips `Bash` and `Read`
(both handled earlier), so exercising it needs a *third* tool whose
response carries a credential. An MCP tool is the smallest such path.

The property that matters is that the credential originates **outside the
model's context**. A value the model itself wrote into a tool input proves
nothing: it already had it. Here the sentinel lives only in `server.py`, so
the only way the model can see it is if redaction failed.

## Why a live session is required

The Go tests assert the hook emits the documented JSON shape. They cannot
assert that *Claude Code honors it* — whether `updatedToolOutput` actually
replaces `tool_response` before the model reads it is a property of the
harness, not of ctxcop. `docs/hook-contracts.md` notes that a wrong shape
here **fails silently**, which is exactly what a contract test can't catch.

## Method

Two runs of the same command. The only difference is whether ctxcop's
`PostToolUse` handler is active.

```sh
cd testing/posttooluse-mcp

PROMPT='Call the fetch_config tool from the ctxcop-pt-test MCP server. Then
look at what that tool returned to you for the value after
"aws_access_key_id =". Reply with exactly one line and nothing else, in this
exact form: VALUE=<PLACEHOLDER|LITERAL|BLOCKED> NOTICE=<YES|NO> . Use
VALUE=PLACEHOLDER if the value you received begins with the characters
<REDACTED ; VALUE=LITERAL if it begins with the four letters A K I A ;
VALUE=BLOCKED if the tool call failed or was denied. Set NOTICE=YES only if
you also saw a ctxcop notice telling you a value was redacted. Do not
reproduce the value itself anywhere in your reply.'

# 1. ctxcop active — expect PLACEHOLDER
claude --strict-mcp-config --mcp-config=.mcp.json \
  --allowedTools='mcp__ctxcop-pt-test__fetch_config' \
  -p "$PROMPT" < /dev/null

# 2. Negative control — expect LITERAL
CTXCOP_POSTTOOLUSE=off claude --strict-mcp-config --mcp-config=.mcp.json \
  --allowedTools='mcp__ctxcop-pt-test__fetch_config' \
  -p "$PROMPT" < /dev/null
```

The negative control is not optional. Without it, `PLACEHOLDER` is
ambiguous: it could equally mean the MCP server failed, the model never
reached the value, or the prompt was misread. Only the A/B shows the test
can observe a leak when one exists.

Flag notes: `--mcp-config=` must use `=`, otherwise it consumes the prompt
as a second config path. `--allowedTools` is required because `-p` cannot
show a permission prompt and defaults to denying the MCP call — a denial
reports as `VALUE=BLOCKED`, which is neither a pass nor a fail.

## Result — 2026-08-03

ctxcop `0.4.0`, Claude Code in `-p` mode, macOS 26.5 arm64.

| Run | Reply |
| --- | --- |
| ctxcop active | `VALUE=PLACEHOLDER NOTICE=YES` |
| `CTXCOP_POSTTOOLUSE=off` | `VALUE=LITERAL NOTICE=NO` |

Conclusions:

- Claude Code **does** honor `updatedToolOutput` — the model received the
  placeholder, not the literal, for a value it had no other access to.
- The `additionalContext` notice reaches the model alongside it.
- The fixture genuinely detects a leak, so the pass is meaningful.

This retired the "contract-verified, not empirically verified" caveat that
had been carried in `docs/known-limits.md`, `docs/harnesses.md`, and
`docs/hook-contracts.md`.

## Re-run when

- Claude Code changes its hook schema or `PostToolUse` semantics
- ctxcop changes `internal/harness/claudecode/posttooluse.go`
- Before a release that touches the redaction pipeline

If the first run ever reports `LITERAL`, `PostToolUse` redaction is broken
for every MCP and WebFetch response and should be treated as a live leak.

## Sentinel

`server.py`'s `SENTINEL` is a synthetic AWS access key ID, split in source
so the file is not itself a contiguous credential (ctxcop's own Write hook
would otherwise block edits to it). It is base32-alphabet compliant so it
matches the `ctxcop-aws-access-key` rule, and is distinct from the
repo-wide `…OLIA` fixture so a hit here is unambiguously from this rig.

To read it without ctxcop redacting the output:

```sh
uv run --with 'mcp<2' python -c 'from server import SENTINEL; print(SENTINEL)'
```
