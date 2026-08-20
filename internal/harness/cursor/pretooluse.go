package cursor

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
	"github.com/webflow/ctxcop/internal/skiplist"
)

type preToolUseInput struct {
	ToolName  string          `json:"tool_name"`
	ToolInput json.RawMessage `json:"tool_input"`
}

// preToolUseOutput is Cursor's flat output. updated_input survives only
// when permission=allow; ignored on deny.
type preToolUseOutput struct {
	Permission   string `json:"permission,omitempty"`
	UserMessage  string `json:"user_message,omitempty"`
	AgentMessage string `json:"agent_message,omitempty"`
	UpdatedInput any    `json:"updated_input,omitempty"`
}

// PreToolUse denies credential-bearing tool inputs. Built-in Cursor tool
// names are case-sensitive (Shell, Write, Read, Grep, Delete, Task);
// MCP arrives as MCP:<server>:<tool>. Fail-open.
func PreToolUse(r io.Reader, w io.Writer) error {
	if pause.IsPaused() {
		return passthrough(w)
	}
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

	switch {
	case in.ToolName == "Shell":
		return denyIfShellHasSecret(in.ToolName, in.ToolInput, w)
	case in.ToolName == "Write":
		return denyIfWriteHasSecret(in.ToolName, in.ToolInput, w)
	case in.ToolName == "Read":
		return redirectIfReadHasSecret(in.ToolName, in.ToolInput, w)
	case strings.HasPrefix(in.ToolName, "MCP:") || strings.HasPrefix(in.ToolName, "mcp__"):
		return denyIfMCPInputHasSecret(in.ToolName, in.ToolInput, w)
	default:
		return passthrough(w)
	}
}

// redirectIfReadHasSecret: postToolUse's updated_mcp_tool_output is
// reliably honored only for MCP tools, so built-in Read responses flow
// through unmodified. We compensate by reading the file ourselves, scanning,
// and redirecting tool_input.file_path to a redacted temp copy via
// updated_input (mirrors Claude Code's pattern). Fail-open on any error
// so a ctxcop bug never breaks a legitimate Read.
func redirectIfReadHasSecret(tool string, raw json.RawMessage, w io.Writer) error {
	var input struct {
		FilePath string `json:"file_path"`
	}
	if err := json.Unmarshal(raw, &input); err != nil || input.FilePath == "" {
		return passthrough(w)
	}
	if skiplist.ShouldSkip(input.FilePath) {
		return passthrough(w)
	}
	data, err := os.ReadFile(input.FilePath)
	if err != nil {
		return passthrough(w)
	}
	// A file being Read is untrusted content flowing into context — do not
	// honor inline allow/fixture markers (issue #56).
	redacted, rules, err := redact.RedactToolOutput(string(data))
	if err != nil || len(rules) == 0 {
		return passthrough(w)
	}
	tmpPath, err := writeRedactedTemp(input.FilePath, redacted)
	if err != nil {
		return passthrough(w)
	}
	audit.Log(audit.Entry{
		Tool:   "Cursor/" + tool,
		Action: "redirected",
		Rules:  rules,
		Count:  len(rules),
		Field:  input.FilePath,
	})
	out := preToolUseOutput{
		Permission:   "allow",
		UpdatedInput: map[string]any{"file_path": tmpPath},
		UserMessage: fmt.Sprintf(
			"ctxcop redirected %s of %q to a redacted temp copy because the file contains apparent %s. "+
				"The model sees placeholders in place of credential-shape values; the original file on disk is untouched. "+
				"If you need the literal value for a tool call, reference it via $ENV_VAR in a shell command instead.",
			tool, input.FilePath, strings.Join(rules, ", ")),
	}
	if err := json.NewEncoder(w).Encode(out); err != nil {
		return passthrough(w)
	}
	return nil
}

func denyIfShellHasSecret(tool string, raw json.RawMessage, w io.Writer) error {
	var input struct {
		Command string `json:"command"`
	}
	if err := json.Unmarshal(raw, &input); err != nil || input.Command == "" {
		return passthrough(w)
	}
	_, rules, err := redact.RedactWithMatches(input.Command)
	if err != nil || len(rules) == 0 {
		return passthrough(w)
	}
	msg := fmt.Sprintf(
		"ctxcop blocked the %s call: the command contains an apparent %s.\n"+
			"\n"+
			"Cursor's preToolUse can't transparently rewrite Shell commands today (updated_input "+
			"behavior on deny is undocumented). Re-issue the command with the secret referenced as "+
			"an env var:\n"+
			"  - Export the value in your shell once, then call: `aws ... --token \"$AWS_TOKEN\" ...`. "+
			"The shell substitutes inside the child process; the literal never enters Cursor's context.\n"+
			"  - If this is genuinely a non-secret string that triggered the detector, prepend "+
			"`# gitleaks:allow` to the relevant line and retry.",
		tool, strings.Join(rules, ", "))
	audit.Log(audit.Entry{Tool: "Cursor/" + tool, Action: "blocked", Rules: rules, Field: "command"})
	return emitDeny(w, msg)
}

func denyIfWriteHasSecret(tool string, raw json.RawMessage, w io.Writer) error {
	var input struct {
		FilePath string `json:"file_path"`
		Content  string `json:"content"`
	}
	if err := json.Unmarshal(raw, &input); err != nil || input.Content == "" {
		return passthrough(w)
	}
	if skiplist.ShouldSkip(input.FilePath) {
		return passthrough(w)
	}
	_, rules, err := redact.RedactWithMatches(input.Content)
	if err != nil || len(rules) == 0 {
		return passthrough(w)
	}
	msg := fmt.Sprintf(
		"ctxcop blocked %s of %q: the content contains an apparent %s.\n"+
			"\n"+
			"Don't write the literal value to disk. Replace it with `process.env.X` / "+
			"`os.Getenv(\"X\")` / `${ENV_VAR}` and load the env var at runtime. If this is "+
			"intentional fixture/seed data, prepend `# gitleaks:allow` (or `# ctxcop:fixture`) "+
			"to the relevant line and retry.",
		tool, input.FilePath, strings.Join(rules, ", "))
	audit.Log(audit.Entry{Tool: "Cursor/" + tool, Action: "blocked", Rules: rules, Field: "content"})
	return emitDeny(w, msg)
}

func denyIfMCPInputHasSecret(tool string, raw json.RawMessage, w io.Writer) error {
	var input any
	if err := json.Unmarshal(raw, &input); err != nil {
		return passthrough(w)
	}
	hit, field, rules := redact.FirstHit(input)
	if !hit {
		return passthrough(w)
	}
	msg := fmt.Sprintf(
		"ctxcop blocked %s: input field %q contains an apparent %s.\n"+
			"\n"+
			"MCP servers run as separate processes. Forwarding a credential through tool_input "+
			"both writes it into your context and hands it to a process that may persist or relay it. "+
			"Configure the MCP server's auth in its own environment block, not via tool_input.",
		tool, field, strings.Join(rules, ", "))
	audit.Log(audit.Entry{Tool: tool, Action: "blocked", Rules: rules, Field: field})
	return emitDeny(w, msg)
}

func emitDeny(w io.Writer, msg string) error {
	out := preToolUseOutput{Permission: "deny", UserMessage: msg}
	if err := json.NewEncoder(w).Encode(out); err != nil {
		return passthrough(w)
	}
	return nil
}

// tempSubdirPrefix must match claudecode's: claudecode's SessionEnd removes
// directories with this prefix under the shared $TMPDIR/ctxcop.
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
// path can't be followed, and no existing file can be clobbered.
//
// Trade-off vs. the old scheme: temp filenames are no longer a stable function
// of the source path, so a re-read of the same file produces a new redacted
// copy rather than reusing one. SessionEnd cleans them all up regardless.
func writeRedactedTemp(origPath, content string) (string, error) {
	dir, err := securetemp.Dir(tempSubdirPrefix + "*")
	if err != nil {
		return "", err
	}
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
