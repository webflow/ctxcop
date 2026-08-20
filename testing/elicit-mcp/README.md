# elicit-mcp — harness test fixture

End-to-end test fixture for ctxcop's Claude Code `ElicitationResult`
hook. Originally built for [#3](https://github.com/webflow/ctxcop/issues/3);
see [RESULT.md](RESULT.md) for that run's findings.

The fixture exists for regression / forward-compat testing: re-run
against future Claude Code releases to confirm that elicitation
`content` still doesn't reach the model context, and to capture any
new payload shape changes (the kind that produced
[#5](https://github.com/webflow/ctxcop/issues/5)).

## Methodology

A minimal MCP server exposes two tools, both of which call `ctx.elicit()`
with the same credential-shape schema. They differ only in what the
tool response returns:

| Tool | Tool response | Isolates |
| --- | --- | --- |
| `echo_form_neutral` | `"form_submitted_neutral"` | Whether `content` itself reaches the transcript, independent of the tool response. |
| `echo_form_verbatim` | the submitted value, echoed back | Sanity check that the sentinel mechanism works. |

The test sentinel is the literal value held in `server.py`'s `SENTINEL`
constant (split-literal in source so the file itself can be edited
under ctxcop). It's credential-shape (matches ctxcop's
`ctxcop-aws-access-key` rule, base32-alphabet compliant) and uniquely
identifiable for grep.

To see the sentinel without ctxcop redacting it:

```sh
.venv/bin/python -c 'from server import SENTINEL; print(SENTINEL)'
```

The local `.ctxcop.toml` allowlists the literal so docs in this
directory can mention it; the global ruleset still detects it
anywhere else.

## Setup

From this directory:

```sh
uv sync
```

That installs the `mcp` SDK into `.venv/`. `.mcp.json` invokes
`uv run python server.py` from cwd.

## Run the experiment

Open a **new Claude Code session** in this directory (separate from
whatever you're using now):

```sh
claude
```

(Approve the MCP server when prompted; `.claude/settings.json`
sets `enableAllProjectMcpServers: true` and `CTXCOP_AUDIT_LOG=./ctxcop-audit.jsonl`.)

### Step 1 — neutral variant

In the Claude session:

> Call the `echo_form_neutral` tool from the ctxcop-elicit-test MCP
> server. Wait for me to fill in the form manually.

When Claude Code shows the elicitation form, type the sentinel into
the `api_key` field and submit.

### Step 2 — verbatim variant (sanity)

> Now call `echo_form_verbatim`.

Type the sentinel into the api_key field again.

### Step 3 — ask Claude what it can see

> Without repeating the literal value: for each of the two form
> submissions (neutral and verbatim), do you have visibility into the
> api_key value I entered? Answer per-variant with 'visible' or 'not
> visible' and briefly cite which message in your context contains it.

This is a third signal alongside the transcript grep.

## Verify

Run these from this directory after the session. The sentinel is
captured into a shell variable so the verify commands don't contain
the literal:

```sh
S=$(.venv/bin/python -c 'from server import SENTINEL; print(SENTINEL)')

# Claude Code encodes cwd into the transcript dir name by replacing
# slashes with dashes. The most-recently-modified match is the active
# session's transcript.
TRANSCRIPT_DIR=~/.claude/projects/$(pwd | sed 's|/|-|g')
ls -lt "$TRANSCRIPT_DIR"

# Grep the transcript(s) for the sentinel.
grep -l "$S" "$TRANSCRIPT_DIR"/*.jsonl

# For each hit, see which message type contains it.
grep -h "$S" "$TRANSCRIPT_DIR"/*.jsonl \
  | jq -c '{type, role: (.message.role // null), preview: ((.message.content // .) | tostring | .[0:240])}'

# What did ctxcop see (via the audit log we configured)?
cat ./ctxcop-audit.jsonl | jq -c '.' || echo "no audit log written"
```

## Interpret

| Neutral-variant sentinel in transcript? | Verbatim-variant sentinel in transcript? | Conclusion |
| --- | --- | --- |
| Yes | Yes (expected) | `content` reaches the model context. **Escalate** ElicitationResult to active mutation. |
| No | Yes | `content` does NOT reach the model context. **Observe-only is correct**; no change to ctxcop. |
| No | No | Test methodology broken (sentinel filter, transport encoding, or transcript layout differs). Diagnose before drawing conclusions. |

In all cases:

- The ctxcop audit log should show one `form-credential-detected` entry
  per tool invocation, naming `api_key` as the flagged field and
  `ctxcop-aws-access-key` as the rule. This confirms the
  ElicitationResult hook fired — independent of whatever Claude did
  with the value.
