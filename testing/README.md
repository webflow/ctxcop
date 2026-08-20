# testing/

Manual end-to-end test fixtures for ctxcop's harness adapters. One
subdir per scenario. These complement (don't replace) the Go unit
tests under `internal/`.

Use these when:

- A new Claude Code / Codex / Cursor / Pi / OpenCode release lands and
  you want to confirm ctxcop's hook integration still holds end-to-end.
- We're investigating an empirical question about a harness's
  behavior that can't be answered from docs alone (see #3).
- We need a regression fixture for an issue that surfaced only with
  a real harness payload (see #5).

Each subdir is self-contained and has its own README with the run
procedure.

## External benchmark

- [docs/agent-egress-bench.md](../docs/agent-egress-bench.md) — how
  ctxcop scores against the applicable (content-DLP) slice of the
  external [agent-egress-bench](https://github.com/luckyPipewrench/agent-egress-bench)
  corpus, with a per-case breakdown and the content-vs-network scope
  boundary. Reproduce steps included; do **not** run AEB's network
  gauntlet runner against ctxcop.

## Fixtures

- [elicit-mcp/](elicit-mcp/) — Claude Code `ElicitationResult` hook;
  minimal MCP server with two elicitation tools (neutral + verbatim)
  for confirming whether form-submission content reaches the model's
  transcript / context window.
