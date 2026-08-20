# Result — webflow/ctxcop#3

Run date: 2026-05-22, Claude Code v2.1.148 (Opus 4.7, 1M context),
ctxcop v0.2.0.

## Answer

**`ElicitationResult.content` does NOT reach the model's transcript
or context window.** The current observe-only behavior of ctxcop's
`ElicitationResult` handler is correct. No code change required.

## Evidence

### Transcript grep

Session transcript:
`~/.claude/projects/-Users-andrewrose-work-ctxcop-elicit-experiment/4f775460-cb51-455c-ba29-144f929bef9a.jsonl`

```
$ grep -c "$SENTINEL" .../4f775460-….jsonl
1
```

One hit total. The single occurrence is on a `type: user`,
`role: user` message containing a `tool_result` for the verbatim
variant:

```json
{
  "type": "user",
  "message": {
    "role": "user",
    "content": [{
      "tool_use_id": "toolu_016eFgMP9WSq3ajKUjzvxf4K",
      "type": "tool_result",
      "content": "{\"result\":\"echoed: api_key=<SENTINEL>, note=\"}"
    }]
  },
  "toolUseResult": "{\"result\":\"echoed: api_key=<SENTINEL>, note=\"}"
}
```

The neutral variant's `tool_use_id` doesn't appear with the sentinel
anywhere in the transcript. Its `tool_result` is the literal string
`{"result":"form_submitted_neutral"}`. The elicitation `content` for
the neutral variant — which DID carry the sentinel through the MCP
protocol back to the server — is recorded NOWHERE in the JSONL.

### Claude's self-report

After both tool calls, asked Claude per-variant whether it could see
the api_key value:

> - `echo_form_neutral`: **not visible**. The tool result was
>   `{"result":"form_submitted_neutral"}` — no field values were
>   carried back through the tool-response path, and no separate
>   elicitation-content channel surfaced them either.
> - `echo_form_verbatim`: **visible**. The tool result for that call
>   contained an `echoed: api_key=…` string with the literal value
>   inline. That tool-result message is the only place in my context
>   where the value appears.

### ctxcop audit log (informational)

From `ctxcop-audit.jsonl`:

```
{"ts":"…","tool":"Elicitation","action":"observed","field":"/"}
{"ts":"…","tool":"Elicitation","action":"observed","field":"/"}
```

Two `Elicitation` entries — one per tool call. The Elicitation hook
(request descriptor before the user sees the form) fires reliably.
The ElicitationResult hook fires too (verified separately via a
stdin-capture wrapper), but no audit entry was written because the
captured payload exposed the parsing bug described below.

## Side-finding: ctxcop hook-input JSON keys are wrong

Captured an actual `ElicitationResult` hook payload from Claude Code
2.1.148:

```json
{
  "session_id": "…",
  "transcript_path": "…",
  "cwd": "…",
  "hook_event_name": "ElicitationResult",
  "mcp_server_name": "ctxcop-elicit-test",
  "mode": "form",
  "action": "accept",
  "content": {
    "note": "",
    "api_key": "<SENTINEL>"
  }
}
```

ctxcop's `elicitationResultInput` struct expects `json:"server_name"`
and `json:"tool_name"`. The payload uses `mcp_server_name` and has NO
`tool_name` field. Same issue in the `Elicitation` handler's
`elicitationInput` struct.

The runtime impact is bounded:

- **Detection still fires.** The `action` and `content` JSON keys are
  correct, so the credential-shape scan still detects sentinels.
- **The notice is degraded.** The systemMessage emitted to the model
  reads `MCP server "" accepted a form-mode elicitation...` (empty
  quotes where the server name should be) because `ServerName`
  unmarshals to an empty string.
- **The audit log `field` is broken.** Entries record
  `field: "/:api_key"` (literally a slash and colon between empty
  strings) because the handler concatenates `ServerName + "/" +
  ToolName + ":" + flaggedFields`.

The `mode` field (`"form"` vs `"url"`) is also new and not handled by
ctxcop today. URL-mode is the spec-approved path for credential
capture, so a future ctxcop would want to skip the notice when
`mode == "url"` (or at least change the wording).

These are separate from issue #3 — file as a follow-up.

## Conclusion

- **Issue #3: close.** Observe-only is the correct stance for
  ElicitationResult. The empirical question is resolved: form-mode
  elicitation `content` is not surfaced to the model and is not
  persisted in the transcript JSONL by Claude Code 2.1.148.
- **Follow-up filed as [#5](https://github.com/webflow/ctxcop/issues/5):**
  fix the struct field names + handle `mode` in both
  `elicitation.go` and `elicitationresult.go`, with a regression test
  that uses a real Claude Code payload shape.
- **Fixture lives in `testing/elicit-mcp/`** in this repo so future
  Claude Code releases can be re-tested against the same methodology.
