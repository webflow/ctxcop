package claudecode

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/webflow/ctxcop/internal/audit"
	"github.com/webflow/ctxcop/internal/pause"
	"github.com/webflow/ctxcop/internal/redact"
	"github.com/webflow/ctxcop/internal/securetemp"
	"github.com/webflow/ctxcop/internal/shellwrap"
)

type preToolUseInput struct {
	ToolName  string          `json:"tool_name"`
	ToolInput json.RawMessage `json:"tool_input"`
}

type hookSpecificOutput struct {
	HookEventName            string         `json:"hookEventName"`
	PermissionDecision       string         `json:"permissionDecision,omitempty"`
	PermissionDecisionReason string         `json:"permissionDecisionReason,omitempty"`
	UpdatedInput             map[string]any `json:"updatedInput,omitempty"`
}

type hookOutput struct {
	HookSpecificOutput hookSpecificOutput `json:"hookSpecificOutput"`
}

// PreToolUse routes by tool_name. Fail-open on every error.
func PreToolUse(self string, r io.Reader, w io.Writer) error {
	raw, err := io.ReadAll(r)
	if err != nil {
		return passthrough(w)
	}
	var in preToolUseInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return passthrough(w)
	}
	if len(in.ToolInput) == 0 {
		return passthrough(w)
	}
	var input map[string]any
	if err := json.Unmarshal(in.ToolInput, &input); err != nil {
		return passthrough(w)
	}

	if pause.IsPaused() {
		return passthrough(w)
	}

	switch {
	case in.ToolName == "Bash":
		return handleBash(self, input, w)
	case in.ToolName == "Read":
		return handleRead(input, w)
	case in.ToolName == "WebFetch":
		return handleWebFetch(input, w)
	case strings.HasPrefix(in.ToolName, "mcp__"):
		return handleMCP(in.ToolName, input, w)
	case in.ToolName == "Agent" || in.ToolName == "Task":
		return handleAgent(input, w)
	default:
		// Any other tool (Write, Edit, MultiEdit, NotebookEdit, or an unknown
		// write-shaped tool) — scan for a write-shaped payload and DENY on a
		// secret. Inverting the old explicit Write/Edit/NotebookEdit allowlist
		// closes the MultiEdit bypass (issue #49); a tool with no write-shaped
		// field falls through to passthrough.
		return handleWriteLike(in.ToolName, input, w)
	}
}

// --- Agent / Task (subagent priming) ---------------------------------------

// agentPrimingMarker prevents double-priming on hook re-fires or
// already-primed prompts.
const agentPrimingMarker = "ctxcop is active in this session"

func handleAgent(input map[string]any, w io.Writer) error {
	prompt, _ := input["prompt"].(string)
	if prompt == "" {
		return passthrough(w)
	}
	if strings.Contains(prompt, agentPrimingMarker) {
		return passthrough(w)
	}

	updated := make(map[string]any, len(input))
	for k, v := range input {
		updated[k] = v
	}
	updated["prompt"] = primingMessage + "\n\n---\n\n" + prompt

	audit.Log(audit.Entry{Tool: "Agent", Action: "primed"})
	// #47: prepend priming via updatedInput WITHOUT asserting
	// permissionDecision. updatedInput is applied regardless of the decision,
	// and omitting it leaves the user's own permission rules governing the
	// subagent launch — emitting "allow" here would silently bypass them.
	return emit(w, hookOutput{HookSpecificOutput: hookSpecificOutput{
		HookEventName: "PreToolUse",
		UpdatedInput:  updated,
	}})
}

// --- Bash -------------------------------------------------------------------

func handleBash(self string, input map[string]any, w io.Writer) error {
	cmd, _ := input["command"].(string)
	if cmd == "" {
		return passthrough(w)
	}
	// #49: scan the command text itself. Wrapping never inspected the command,
	// so a `cat > f <<EOF … AKIA… EOF` heredoc or a
	// `curl -H "Authorization: Bearer ghp_…"` slipped a literal secret past
	// ctxcop. DENY-with-guidance mirrors the cursor/codex Shell handlers.
	// (Scanning before the already-wrapped check is safe: ctxcop only ever
	// wraps secret-free commands, so a re-fired wrap can't newly hit here.)
	if _, rules, err := redact.RedactWithMatches(cmd); err == nil && len(rules) > 0 {
		reason := fmt.Sprintf(
			"ctxcop blocked the Bash call: the command contains an apparent %s.\n"+
				"\n"+
				"Don't put the literal secret in the command. Re-issue it with the value referenced as an env var:\n"+
				"  - Export it once in your shell, then call e.g. `curl -H \"Authorization: Bearer $TOKEN\" …` or `aws … --token \"$AWS_TOKEN\" …`. "+
				"The shell substitutes inside the child process; the literal never enters your context.\n"+
				"  - A heredoc that writes a secret to a file has the same problem — write `${TOKEN}` (or a `<placeholder>`) and let the runtime resolve it.\n"+
				"  - If this is genuinely a non-secret string that tripped the detector, prepend `# gitleaks:allow` to the relevant line and retry.",
			strings.Join(rules, ", "))
		audit.Log(audit.Entry{Tool: "Bash", Action: "blocked", Rules: rules, Field: "command"})
		return emit(w, denyOutput(reason))
	}
	if isAlreadyWrapped(cmd, self) {
		return passthrough(w)
	}
	bg, _ := input["run_in_background"].(bool)
	subcmd := "run"
	if bg {
		subcmd = "run --stream"
	}
	// Wrap in `bash -c '<cmd>'` so shell builtins, pipelines, and heredocs
	// keep their semantics. Without -c, exec uses argv[0] directly.
	wrapped := fmt.Sprintf("%s %s -- bash -c %s", shellwrap.Quote(self), subcmd, shellwrap.Quote(cmd))

	updated := make(map[string]any, len(input))
	for k, v := range input {
		updated[k] = v
	}
	updated["command"] = wrapped

	audit.Log(audit.Entry{Tool: "Bash", Action: "wrapped"})
	// #47: apply the wrap via updatedInput but DO NOT assert permissionDecision.
	// Per the Claude Code hooks contract, updatedInput is applied regardless of
	// permissionDecision, and omitting the decision means "no decision" so the
	// user's own permission rules still govern the (rewritten) command.
	// Emitting "allow" here — as ctxcop did before — silently converted the
	// user's per-command prompt/deny rules into unattended auto-run.
	return emit(w, hookOutput{HookSpecificOutput: hookSpecificOutput{
		HookEventName: "PreToolUse",
		UpdatedInput:  updated,
	}})
}

// --- Read -------------------------------------------------------------------

func handleRead(input map[string]any, w io.Writer) error {
	path, _ := input["file_path"].(string)
	if path == "" {
		return passthrough(w)
	}
	if shouldSkipPath(path) {
		return passthrough(w)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return passthrough(w)
	}
	// A file being Read is untrusted content flowing into context — do not
	// honor inline allow/fixture markers (issue #56).
	red, rules, err := redact.RedactToolOutput(string(data))
	if err != nil || len(rules) == 0 {
		return passthrough(w)
	}
	tmpPath, err := writeRedactedTemp(path, red)
	if err != nil {
		return passthrough(w)
	}

	updated := make(map[string]any, len(input))
	for k, v := range input {
		updated[k] = v
	}
	updated["file_path"] = tmpPath

	audit.Log(audit.Entry{Tool: "Read", Action: "redacted", Rules: rules, Count: len(rules)})
	// #47: redirect the Read to the redacted copy via updatedInput; no
	// permissionDecision, so the user's permission rules still apply.
	return emit(w, hookOutput{HookSpecificOutput: hookSpecificOutput{
		HookEventName: "PreToolUse",
		UpdatedInput:  updated,
	}})
}

// --- Write / Edit / NotebookEdit -------------------------------------------

func handleWriteLike(tool string, input map[string]any, w io.Writer) error {
	for _, pathField := range []string{"file_path", "notebook_path"} {
		if p, _ := input[pathField].(string); shouldSkipPath(p) {
			return passthrough(w)
		}
	}
	for _, sf := range collectWriteShaped(input) {
		_, rules, err := redact.RedactWithMatches(sf.value)
		if err != nil || len(rules) == 0 {
			continue
		}
		reason := fmt.Sprintf(
			"ctxcop blocked %s: field %q contains an apparent %s.\n"+
				"\n"+
				"Don't write the literal value. Pick one of:\n"+
				"  - In code: reference it via `process.env.NAME` / `os.Getenv(\"NAME\")` / `${NAME}` and load the env var at runtime.\n"+
				"  - In config/template files: use a placeholder like `<your-%s>` and document the expected env var.\n"+
				"  - If this is an intentional fixture/seed value, prefix the literal with `# gitleaks:allow` or `# ctxcop:fixture` on the same line.\n"+
				"\n"+
				"Retry with one of those forms.",
			tool, sf.field, strings.Join(rules, ", "), rules[0])
		return emit(w, blockOrWarn(tool, sf.field, reason, rules))
	}
	return passthrough(w)
}

// writeField is a write-shaped string payload plus its dotted-path label.
type writeField struct {
	field string
	value string
}

// isWriteShapedKey matches keys that carry file-content payloads across the
// Write / Edit / MultiEdit / NotebookEdit family: "content", any *_string
// (old_string / new_string), and any *_source (new_source). Matching by shape
// rather than an exact tool-name allowlist is what closes the MultiEdit and
// unknown-write-tool bypasses (issue #49).
func isWriteShapedKey(k string) bool {
	return k == "content" || strings.HasSuffix(k, "_string") || strings.HasSuffix(k, "_source")
}

// collectWriteShaped gathers write-shaped string values from a tool input,
// recursing into a nested edits[] array (MultiEdit) so each per-edit
// new_string is scanned too.
func collectWriteShaped(input map[string]any) []writeField {
	var out []writeField
	add := func(prefix string, m map[string]any) {
		for k, v := range m {
			s, ok := v.(string)
			if !ok || s == "" || !isWriteShapedKey(k) {
				continue
			}
			field := k
			if prefix != "" {
				field = prefix + "." + k
			}
			out = append(out, writeField{field: field, value: s})
		}
	}
	add("", input)
	if edits, ok := input["edits"].([]any); ok {
		for i, e := range edits {
			if m, ok := e.(map[string]any); ok {
				add(fmt.Sprintf("edits[%d]", i), m)
			}
		}
	}
	return out
}

// --- WebFetch ---------------------------------------------------------------

func handleWebFetch(input map[string]any, w io.Writer) error {
	for _, field := range []string{"url", "prompt"} {
		v, _ := input[field].(string)
		if v == "" {
			continue
		}
		_, rules, err := redact.RedactWithMatches(v)
		if err != nil || len(rules) == 0 {
			continue
		}
		reason := fmt.Sprintf(
			"ctxcop blocked WebFetch: field %q contains an apparent %s.\n"+
				"\n"+
				"WebFetch's tool_input is visible to Claude verbatim — putting a credential here writes it into your context AND sends it to the remote host. Instead:\n"+
				"  - Switch to Bash and call curl with the credential from an env var:\n"+
				"      curl -H \"Authorization: Bearer $TOKEN\" https://api.example.com/…\n"+
				"    The env var is substituted in the child shell; the value never enters your context.\n"+
				"  - If you only need to inspect public response shape, drop the credential entirely and retry.\n"+
				"\n"+
				"Retry with curl-via-Bash or no credential.",
			field, strings.Join(rules, ", "))
		return emit(w, blockOrWarn("WebFetch", field, reason, rules))
	}
	return passthrough(w)
}

// --- MCP --------------------------------------------------------------------

func handleMCP(tool string, input map[string]any, w io.Writer) error {
	// MCP schemas vary; scan every string value rather than known fields.
	hits, firstField, rules := redact.FirstHit(input)
	if !hits {
		return passthrough(w)
	}
	reason := fmt.Sprintf(
		"ctxcop blocked %s: input field %q contains an apparent %s.\n"+
			"\n"+
			"MCP servers run as separate processes (often shipped by third parties). Forwarding a credential through tool_input both (a) writes it into your context and (b) hands it to a process that may persist or relay it. Instead:\n"+
			"  - If this MCP server NEEDS auth, configure it server-side in `.mcp.json` (env block) — the server reads its credential from its own environment, never via tool_input.\n"+
			"  - If you were including the secret as evidence/debug context, drop it from the message; reference it abstractly (\"the production AWS key\") if the user needs the reference.\n"+
			"\n"+
			"Retry with the credential removed from tool_input.",
		tool, firstField, strings.Join(rules, ", "))
	return emit(w, blockOrWarn(tool, firstField, reason, rules))
}

// --- shared -----------------------------------------------------------------

func emit(w io.Writer, out hookOutput) error {
	return json.NewEncoder(w).Encode(out)
}

// denyOutput builds a hard-DENY PreToolUse response with retry guidance.
// Unlike blockOrWarn this is not downgradable by dev-warn: a secret embedded
// directly in a Bash command is always denied, mirroring the cursor/codex
// Shell handlers (whose behavior CTXCOP_DEV=warn has never governed).
func denyOutput(reason string) hookOutput {
	return hookOutput{HookSpecificOutput: hookSpecificOutput{
		HookEventName:            "PreToolUse",
		PermissionDecision:       "deny",
		PermissionDecisionReason: reason,
	}}
}

// tempSubdirPrefix names the per-invocation subdirectory that holds a redacted
// copy. Both claudecode and cursor create directories with this prefix under
// $TMPDIR/ctxcop, and claudecode's SessionEnd recognizes and removes them.
const tempSubdirPrefix = "redact-"

// writeRedactedTemp writes redacted content to a fresh, unpredictable temp
// file and returns its path.
//
// Issue #48: the old scheme derived the path from sha256(abspath) inside a
// shared dir created with MkdirAll (which succeeds on a pre-existing dir of
// any owner/mode) and wrote with os.WriteFile (follows symlinks). On CI/Linux
// where TMPDIR is unset this landed in world-writable /tmp at a guessable
// path, enabling arbitrary-file overwrite and content-swap context injection
// via a planted symlink. We now create a fresh per-invocation subdirectory via
// os.MkdirTemp (unpredictable name, mode 0700) and open the file with
// O_CREATE|O_EXCL|O_WRONLY 0600 — so a symlink pre-planted at any guessable
// path can't be followed, and no existing file can be clobbered. This needs no
// new dependency (no x/sys O_NOFOLLOW).
func writeRedactedTemp(origPath, content string) (string, error) {
	dir, err := securetemp.Dir(tempSubdirPrefix + "*")
	if err != nil {
		return "", err
	}
	// Preserve the basename so extension-based routing on file_path is intact.
	tmpPath := filepath.Join(dir, filepath.Base(origPath))
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	if _, err := f.WriteString(content); err != nil {
		_ = f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	return tmpPath, nil
}

func passthrough(w io.Writer) error {
	_, _ = io.WriteString(w, "{}\n")
	return nil
}

// isAlreadyWrapped guards against re-firing on commands ctxcop already wrapped.
func isAlreadyWrapped(command, self string) bool {
	trimmed := strings.TrimLeft(command, " \t")
	for _, p := range []string{
		self + " run ",
		shellwrap.Quote(self) + " run ",
		"ctxcop run ",
	} {
		if strings.HasPrefix(trimmed, p) {
			return true
		}
	}
	return false
}
