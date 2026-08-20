// Package harness organizes ctxcop's per-AI-agent-harness integration code.
//
// Each subpackage targets one harness — Claude Code (./claudecode),
// Codex CLI (./codex), Cursor (./cursor), Pi (./pi), and OpenCode
// (./opencode). The first three use a strikingly similar pattern: an
// external binary invoked at well-defined lifecycle events with JSON
// arriving on stdin and JSON decisions returned on stdout. Cursor and
// Codex CLI even use overlapping field names (hookSpecificOutput,
// permissionDecision, continue, stopReason). Pi and OpenCode are the
// in-process outliers — TypeScript modules loaded by the harness's own
// runtime, integrated via a thin bridge that shells out to ctxcop.
//
// A harness package is expected to provide:
//
//   - Per-event handler functions matching that harness's lifecycle.
//     Function signature is conventionally func(io.Reader, io.Writer) error,
//     reading the hook payload from stdin and writing the hook response
//     to stdout. Fail-open: any internal error returns "{}\n" so a ctxcop
//     bug never blocks a real tool call.
//
//   - An Install function that registers ctxcop's handlers in whatever
//     settings/config file the harness uses (settings.json for Claude
//     Code, config.toml for Codex, hooks.json for Cursor; for Pi and
//     OpenCode, the embedded TypeScript bridge is written to
//     ~/.pi/agent/extensions/ and ~/.config/opencode/plugins/
//     respectively). Install is idempotent and preserves unrelated
//     entries.
//
//   - Where applicable, a priming/session-start message that primes the
//     model with the conventions it should follow alongside ctxcop.
//
// What is NOT in a harness package: anything that's actually harness-
// agnostic — redaction (./internal/redact), rule loading (./internal/rules),
// audit logging (./internal/audit), the wrapped-command runner
// (./internal/runner), pause semantics (./internal/pause). Those are
// imported by every harness; the harness package is the adapter that
// glues them to the host-specific event names and JSON shapes.
//
// Adding a new harness: create a sibling subpackage, implement the
// event handlers and Install, and add a top-level subcommand to
// cmd/ctxcop/main.go that routes to them. Strong test coverage of
// the JSON shapes per event is non-negotiable — Claude Code's
// UserPromptSubmit shape bug (commit 1adab3e) was a silent-success-
// with-wrong-shape failure, the worst class for a security control.
package harness
