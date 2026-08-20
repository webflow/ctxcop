package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strings"

	"github.com/webflow/ctxcop/internal/audit"
	"github.com/webflow/ctxcop/internal/harness/aider"
	"github.com/webflow/ctxcop/internal/harness/claudecode"
	"github.com/webflow/ctxcop/internal/harness/codex"
	"github.com/webflow/ctxcop/internal/harness/cursor"
	"github.com/webflow/ctxcop/internal/harness/opencode"
	"github.com/webflow/ctxcop/internal/harness/pi"
	"github.com/webflow/ctxcop/internal/pause"
	"github.com/webflow/ctxcop/internal/redact"
	"github.com/webflow/ctxcop/internal/rules"
	"github.com/webflow/ctxcop/internal/runner"
	"github.com/webflow/ctxcop/internal/shellwrap"
	"github.com/webflow/ctxcop/internal/skiplist"
)

// version is set via -X main.version=vX.Y.Z; falls back to ReadBuildInfo.
var version string

func init() {
	// Wire the rules package's project-config skip_paths into the
	// shared skiplist used by every harness. Done here (rather than at
	// the package level inside skiplist) so the rules package can stay
	// free of harness/skip concerns and vice versa.
	skiplist.SkipPathsFromProject = rules.ProjectSkipPaths
}

const usage = `ctxcop — keep secrets out of Claude Code's context window

USAGE:
  ctxcop <subcommand> [args...]

SUBCOMMANDS:
  run [--stream] -- <cmd> [args...]
        Execute <cmd> and redact secrets in its stdout/stderr before they
        reach the caller. Passes through the child's exit code (128+N for
        signal terminations). Use --stream for long-running / background
        commands where output is consumed incrementally (line-buffered).

  scan
        Read stdin, redact secrets, write to stdout. No child process.
        Useful for piping arbitrary text through the redactor.

  hook pre-tool-use
        Claude Code PreToolUse handler. Reads the hook payload from stdin
        on each tool call and emits an updatedInput / permissionDecision
        JSON response. Bash calls are rewritten to "ctxcop run --"
        (auto-selects --stream for run_in_background); Read paths are
        redirected to a redacted temp copy; Write/Edit/WebFetch/MCP inputs
        containing apparent secrets are blocked with a guidance reason.
        Fail-open: any internal error returns {} so the original tool call
        proceeds.

  hook post-tool-use
        Claude Code PostToolUse handler. Scans tool_response for tools
        whose output PreToolUse cannot redact in flight (WebFetch, mcp__*,
        and any tool other than Bash/Read). Cannot un-leak — the response
        is already in context — but emits an additionalContext warning so
        the model knows to treat the value as compromised and not propagate
        it, and writes an audit entry.

  hook user-prompt-submit
        Claude Code UserPromptSubmit handler. Blocks the user's prompt if
        it contains apparent secrets (e.g. the user pasted a credential
        into chat). The denial reason guides the user to re-submit with
        the secret removed, an abstract reference, or a shell env var.

  hook session-start
        Claude Code SessionStart handler. Emits a concise additionalContext
        priming message teaching the agent how to work alongside ctxcop
        (env-var substitution, field projection, curl-via-Bash, etc.).

  hook session-end
        Claude Code SessionEnd handler. Cleans up the redacted-copy temp
        files Read interception writes to $TMPDIR/ctxcop/. Prior
        sessions' leftovers (>24h old) also get pruned.

  hook pre-compact
        Claude Code PreCompact handler. Fires before context compaction.
        Scans the transcript for apparent secrets and emits a systemMessage
        warning the model that any credential-shaped text in the upcoming
        summary inherits the source. Cannot modify the compaction;
        observation + soft warning only.

  hook post-compact
        Claude Code PostCompact handler. Fires after a compaction completes.
        Scans the post-compaction transcript and warns if credential-shaped
        text materialized in the summary (which can happen even when the
        source was redaction-clean — the summarizer can re-synthesize
        patterns). Observation + soft warning.

  hook elicitation
        Claude Code Elicitation handler. Fires when an MCP server requests
        structured user input. ctxcop observes + audit-logs; the chokepoint
        for credential leakage is elicitation-result.

  hook elicitation-result
        Claude Code ElicitationResult handler. Fires after the user has
        answered an MCP form, before the response is sent to the MCP server.
        Scans the user's answers for apparent secrets and emits a top-level
        systemMessage pointing at the MCP spec (form-mode is explicitly
        forbidden from carrying credentials per
        modelcontextprotocol.io/specification/2025-06-18). Observe-only
        in v0.2.0 — does not modify the submission.

  hook codex <event>
        Codex CLI handler entrypoint. <event> is one of pre-tool-use,
        post-tool-use, user-prompt-submit, session-start. Behavioral
        differences from Claude Code:
          - PreToolUse: blocks credential-bearing inputs via
            permissionDecision="deny". Cannot transparently rewrite
            commands (Codex's updatedInput is rejected at runtime today,
            github.com/openai/codex#18491), so engineers must reference
            secrets via $ENV_VAR before invocation.
          - PostToolUse: BLOCKS tool responses containing credential-
            shape data via top-level decision="block" + reason. We
            deliberately do NOT use hookSpecificOutput.updatedMCPToolOutput
            — Codex documents that field as "parsed but not supported
            yet" (fails open), which would silently leak the credential
            while making ctxcop think it had been redacted. Whole-
            response blocking is the conservative-correct semantic on
            today's Codex.

  hook cursor <event>
        Cursor handler entrypoint. <event> is one of pre-tool-use,
        post-tool-use, before-submit-prompt, session-start. Behavioral
        differences:
          - Uses Cursor's flat output shape (permission/user_message)
            rather than nested hookSpecificOutput. Cursor parses both
            shapes; flat is the documented preferred form.
          - postToolUse redacts via updated_mcp_tool_output. Documented
            as generic but reliably consumed only by MCP-prefixed tools
            today — best-effort for Shell/Write/Read responses.
          - Tool names: Shell (not Bash), Write (covers Edit), Read,
            Grep, Delete, Task; MCP tools arrive as "MCP:<server>:<tool>".
          - Upstream bugs (open as of May 2026): WebSearch + AskQuestion
            never trigger hooks; additional_context is parsed but not
            surfaced to the model. ctxcop emits user_message instead.

  hook aider <event>
        Aider handler entrypoint. Aider has no runtime hook lifecycle
        (Aider-AI/aider#4485 closed, #5300 closed; upstream in
        maintenance mode), so ctxcop's integration is static: install
        wraps lint-cmd / test-cmd through the ` + "`ctxcop run`" + ` runner
        and pins a priming file via Aider's ` + "`read:`" + ` config key.
        <event> today is:
          - preflight [--project-root <path>]
            Scan the project's .env for credential-shape values before
            ` + "`aider`" + ` runs. Not automatic — Aider has no hook to fire it
            from. The priming file suggests a shell alias:
                alias aider='ctxcop hook aider preflight && aider'

  rules list
        List every detection rule the redactor knows about, with provenance
        (upstream-default | ctxcop-embedded | user-file | project-file |
        env-file) and disabled state. Useful for auditing what's active and
        identifying candidates for $CTXCOP_DISABLE_RULES.

  audit verify [--log <path>]
        Walk the audit log and verify each entry's hash matches its
        recomputed value AND its Prev field links to the previous
        entry's Hash — the chain ctxcop writes on every Log() call.
        Reports tampered/reordered/removed entries by line number.
        Defaults to $CTXCOP_AUDIT_LOG. Legacy entries (no Hash, from
        pre-chain ctxcop versions) are surfaced separately and don't
        fail the check.

  pause [--for <duration>]
        Suspend all ctxcop hook activity until the duration elapses (default
        1h). Every PreToolUse/PostToolUse/UserPromptSubmit call passes through
        unchanged while paused. For when you're iterating on fixtures and
        the hooks are getting in your way.

  resume
        End an active pause immediately. Idempotent.

  status
        Show whether ctxcop is active or paused (with remaining time).

  uninstall [--scope user|project] [--harness claude-code|codex|cursor|pi|opencode|aider|all] [--yes]
        Remove ctxcop's hook entries from harness config files. Default
        --harness=all scans every supported harness for ctxcop entries
        and removes them. Preserves all unrelated config (user-added
        hooks, model settings, MCP servers, etc.). Idempotent — running
        on a clean machine prints "nothing was removed" and exits 0.

        Prompts for confirmation (y/N) by default since uninstall
        mutates files across $HOME. Pass --yes to skip the prompt
        (scripts, CI, automation). An explicit --harness=X is treated
        as already-confirmed and does not prompt. Non-TTY invocations
        without --yes refuse to write (fail-closed default).

        Recommended before removing the ctxcop binary itself: if the
        binary is removed before the hooks are deregistered, the harness
        will try to exec a nonexistent path on every tool call. Most
        harnesses fail open but log noise; this command is the clean
        path.

  install [--scope user|project] [--harness claude-code|codex|cursor|pi|opencode|aider|auto] [--yes]
        Autodetect which AI agent harnesses are present on this machine
        (~/.claude/, ~/.codex/, ~/.cursor/) and register ctxcop's hooks
        in each. Pass --harness=X to install for a specific harness
        regardless of detection (useful in CI / scripted installs).
        Idempotent — re-installing replaces prior ctxcop entries
        without touching unrelated config (user-managed model settings,
        MCP servers, non-ctxcop hooks).

        Prompts for confirmation (y/N) by default in the autodetect
        path, listing the harnesses + paths that will be written.
        --yes skips the prompt. An explicit --harness=X is treated
        as already-confirmed and does not prompt. Non-TTY invocations
        without --yes refuse to write (fail-closed default).

        - Claude Code: writes ~/.claude/settings.json (or ./.claude/
          settings.json with --scope=project). Hooks: PreToolUse,
          PostToolUse, UserPromptSubmit, SessionStart, SessionEnd,
          PreCompact, PostCompact, Elicitation, ElicitationResult.
        - Codex CLI: writes ~/.codex/config.toml. Hooks: PreToolUse,
          PostToolUse, UserPromptSubmit, SessionStart. Caveat: Codex
          hooks intercept only the standard shell-tool payload shape;
          unified_exec, local_shell, and streaming shell variants
          bypass ctxcop silently.
        - Cursor: writes ~/.cursor/hooks.json. Hooks: preToolUse,
          postToolUse, beforeSubmitPrompt, sessionStart. Caveats:
          WebSearch and AskQuestion bypass Cursor hooks today (upstream
          bugs, open as of May 2026); additional_context from
          postToolUse / sessionStart is parsed but not surfaced to the
          model — ctxcop uses user_message instead, which works.
        - Aider: writes ~/.aider.conf.yml (or ./.aider.conf.yml with
          --scope=project). No runtime hooks — Aider is in maintenance
          mode with no hook lifecycle. ctxcop wraps existing lint-cmd
          and test-cmd values through ` + "`ctxcop run -- bash -c '<cmd>'`" + ` so
          the whole original command (including compound commands and
          env-var prefixes) keeps its shell semantics and its output
          flows through the redactor before Aider feeds it back to the
          model, and pins ~/.aider/ctxcop-priming.md via the
          ` + "`read:`" + ` config key as a SessionStart-equivalent. Coverage is
          narrower than the hook-based harnesses (no UserPromptSubmit
          analogue, no interposition on the LiteLLM round-trip); see
          docs/harnesses.md#aider.

  help | -h | --help
        Show this message.

ENVIRONMENT:
  CTXCOP_AUDIT_LOG
        Path to an append-only JSONL audit log. Unset = no logging (the
        default — security tooling shouldn't silently retain detection
        records alongside the secrets that triggered them). One line per
        event: {ts, tool, action, rules, count, field}.

  CTXCOP_RULES
        Path to an extra TOML file of detection rules, merged on top of
        the upstream default + ctxcop embedded packs. Rules with the same
        ID override earlier sources. Same TOML schema as gitleaks.

  CTXCOP_DISABLE_RULES
        Comma-separated list of rule IDs to remove from the composed
        ruleset. Use after running "ctxcop rules list" to identify a
        noisy rule.

  CTXCOP_SKIP_PATHS
        Comma-separated glob list of file paths whose Read/Write/Edit
        operations should not be scanned. Adds to ctxcop's built-in defaults
        (testdata/, fixtures/, *_test.*, *.test.*, *.spec.*, *.fixture.*,
        *.golden, etc.) and any skip_paths declared in a project .ctxcop.toml.
        Globs support **/X/**, **/X, X/**, *.ext, and basename matches.

  CTXCOP_DEV
        Set to "warn" to downgrade Write/Edit/WebFetch/MCP blocks to
        allow + warning. UserPromptSubmit and the Bash/Read transparent
        rewrites are unaffected. Audit logs the downgrade as
        "blocked-downgraded". Useful when iterating on test fixtures.

  CTXCOP_POSTTOOLUSE
        Set to "off" to disable the PostToolUse warning hook entirely
        (e.g. if the noise outweighs the signal for your workflow).
        Unset / any other value = normal behavior.

  CTXCOP_POSTTOOLUSE_ALLOW
        Comma-separated list of tool-name globs whose responses should
        NOT trigger a PostToolUse warning. For tools whose purpose IS to
        return secrets (vault, 1password, secrets-manager MCPs, etc.) —
        the model still sees the value but gets no ctxcop notice.
        The audit log records a "warned-suppressed" entry. The only
        wildcard is *. Example:
            CTXCOP_POSTTOOLUSE_ALLOW='mcp__vault__*,mcp__1password__*,*secret*'

EXAMPLES:
  ctxcop scan < some-log.txt
  ctxcop run -- aws sts get-caller-identity
  ctxcop install --scope user
  ctxcop pause --for 30m            # iterating on fixtures
  CTXCOP_DEV=warn claude            # downgrade blocks to warnings
  CTXCOP_AUDIT_LOG=$HOME/cc-audit.jsonl claude

PROJECT CONFIG:
  A .ctxcop.toml at your project root (discovered by walking up from
  the cwd, max 8 levels) is loaded alongside the embedded rule pack and
  user rules. Supports two extras on top of the gitleaks rule schema:
    skip_paths = ["my-fixtures/**", "*.snapshot"]   # adds to skip-list

  Standard gitleaks [[rules]] and [[allowlists]] blocks work as-is.

FIXTURE ANNOTATION:
  Append ` + "`ctxcop:fixture`" + ` (or ` + "`ctxcop:allow`" + ` or ` + "`gitleaks:allow`" + `) on
  the same line as an intentional credential-shaped literal — that line is
  excluded from detection.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	ctx := context.Background()
	switch os.Args[1] {
	case "run":
		os.Exit(cmdRun(ctx, os.Args[2:]))
	case "scan":
		os.Exit(cmdScan())
	case "hook":
		os.Exit(cmdHook(os.Args[2:]))
	case "install":
		os.Exit(cmdInstall(os.Args[2:]))
	case "uninstall":
		os.Exit(cmdUninstall(os.Args[2:]))
	case "rules":
		os.Exit(cmdRules(os.Args[2:]))
	case "audit":
		os.Exit(cmdAudit(os.Args[2:]))
	case "pause":
		os.Exit(cmdPause(os.Args[2:]))
	case "resume":
		os.Exit(cmdResume())
	case "status":
		os.Exit(cmdStatus())
	case "-h", "--help", "help":
		fmt.Print(usage)
		os.Exit(0)
	case "-v", "--version", "version":
		fmt.Println(resolveVersion())
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "ctxcop: unknown subcommand %q\n%s", os.Args[1], usage)
		os.Exit(2)
	}
}

func cmdRun(ctx context.Context, args []string) int {
	stream := false
	for len(args) > 0 && args[0] != "--" {
		switch args[0] {
		case "--stream":
			stream = true
			args = args[1:]
		default:
			fmt.Fprintf(os.Stderr, "ctxcop: unknown flag %q (did you forget '--' before the command?)\n", args[0])
			return 2
		}
	}
	if len(args) == 0 || args[0] != "--" {
		fmt.Fprintln(os.Stderr, "ctxcop: expected '--' separator before child command")
		return 2
	}
	argv := args[1:]
	if len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "ctxcop: no command after '--'")
		return 2
	}
	if stream {
		code, err := runner.RunStreaming(ctx, argv, os.Stdout, os.Stderr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ctxcop: %v\n", err)
		}
		return code
	}
	code, err := runner.Run(ctx, argv, os.Stdout, os.Stderr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ctxcop: %v\n", err)
	}
	return code
}

func cmdScan() int {
	data, err := io.ReadAll(bufio.NewReader(os.Stdin))
	if err != nil {
		fmt.Fprintf(os.Stderr, "ctxcop: read stdin: %v\n", err)
		return 1
	}
	out, err := redact.Redact(string(data))
	if err != nil {
		fmt.Fprintf(os.Stderr, "ctxcop: redact failed, passing through: %v\n", err)
		out = string(data)
	}
	_, _ = io.WriteString(os.Stdout, out)
	return 0
}

func cmdHook(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "ctxcop: hook requires an event name (pre-tool-use | session-start | ... | codex <event>)")
		return 0 // fail open
	}
	// `ctxcop hook <harness> <event>` routes to the named adapter;
	// everything else stays on the (default) Claude Code adapter so
	// existing settings.json registrations don't break.
	switch args[0] {
	case "codex":
		return cmdHookCodex(args[1:])
	case "cursor":
		return cmdHookCursor(args[1:])
	case "pi":
		return cmdHookPi(args[1:])
	case "opencode":
		return cmdHookOpenCode(args[1:])
	case "aider":
		return cmdHookAider(args[1:])
	}
	var err error
	switch args[0] {
	case "pre-tool-use":
		err = claudecode.PreToolUse(shellwrap.SelfPath(), os.Stdin, os.Stdout)
	case "session-start":
		err = claudecode.SessionStart(os.Stdout)
	case "post-tool-use":
		err = claudecode.PostToolUse(os.Stdin, os.Stdout)
	case "user-prompt-submit":
		err = claudecode.UserPromptSubmit(os.Stdin, os.Stdout)
	case "session-end":
		err = claudecode.SessionEnd(os.Stdout)
	case "pre-compact":
		err = claudecode.PreCompact(os.Stdin, os.Stdout)
	case "post-compact":
		err = claudecode.PostCompact(os.Stdin, os.Stdout)
	case "elicitation":
		err = claudecode.Elicitation(os.Stdin, os.Stdout)
	case "elicitation-result":
		err = claudecode.ElicitationResult(os.Stdin, os.Stdout)
	default:
		fmt.Fprintf(os.Stderr, "ctxcop: unknown hook event %q\n", args[0])
		return 0 // fail open
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "ctxcop: hook error: %v\n", err)
	}
	return 0
}

// cmdHookCodex routes `ctxcop hook codex <event>`.
func cmdHookCodex(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "ctxcop: hook codex requires an event name (pre-tool-use | post-tool-use | user-prompt-submit | session-start)")
		return 0
	}
	var err error
	switch args[0] {
	case "pre-tool-use":
		err = codex.PreToolUse(os.Stdin, os.Stdout)
	case "post-tool-use":
		err = codex.PostToolUse(os.Stdin, os.Stdout)
	case "user-prompt-submit":
		err = codex.UserPromptSubmit(os.Stdin, os.Stdout)
	case "session-start":
		err = codex.SessionStart(os.Stdout)
	default:
		fmt.Fprintf(os.Stderr, "ctxcop: unknown codex hook event %q\n", args[0])
		return 0
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "ctxcop: codex hook error: %v\n", err)
	}
	return 0
}

// cmdHookCursor routes `ctxcop hook cursor <event>`.
func cmdHookCursor(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "ctxcop: hook cursor requires an event name (pre-tool-use | post-tool-use | before-submit-prompt | session-start)")
		return 0
	}
	var err error
	switch args[0] {
	case "pre-tool-use":
		err = cursor.PreToolUse(os.Stdin, os.Stdout)
	case "post-tool-use":
		err = cursor.PostToolUse(os.Stdin, os.Stdout)
	case "before-submit-prompt":
		err = cursor.BeforeSubmitPrompt(os.Stdin, os.Stdout)
	case "session-start":
		err = cursor.SessionStart(os.Stdout)
	default:
		fmt.Fprintf(os.Stderr, "ctxcop: unknown cursor hook event %q\n", args[0])
		return 0
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "ctxcop: cursor hook error: %v\n", err)
	}
	return 0
}

// cmdHookPi routes `ctxcop hook pi <event>` — invoked by the TS bridge.
// Three events: before-provider-request (chokepoint), before-agent-start
// (priming), tool-call (MCP exfil block). See docs/harnesses.md.
func cmdHookPi(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "ctxcop: hook pi requires an event name (before-provider-request | before-agent-start | tool-call)")
		return 0
	}
	var err error
	switch args[0] {
	case "before-provider-request":
		err = pi.BeforeProviderRequest(os.Stdin, os.Stdout)
	case "before-agent-start":
		err = pi.BeforeAgentStart(os.Stdin, os.Stdout)
	case "tool-call":
		err = pi.ToolCall(os.Stdin, os.Stdout)
	default:
		fmt.Fprintf(os.Stderr, "ctxcop: unknown pi hook event %q\n", args[0])
		return 0
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "ctxcop: pi hook error: %v\n", err)
	}
	return 0
}

// cmdHookAider routes `ctxcop hook aider <event>`. Aider has no
// runtime hook lifecycle (Aider-AI/aider#4485 closed, #5300 closed;
// project in maintenance mode), so the "event" here is a manual
// invocation the user or a shell alias fires. Today: `preflight`,
// which scans the project's .env for credential-shape values before
// `aider` runs. See docs/harnesses.md#aider for how to wire it into
// a shell alias.
func cmdHookAider(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "ctxcop: hook aider requires an event name (preflight)")
		return 0
	}
	switch args[0] {
	case "preflight":
		root := ""
		for i := 1; i < len(args); i++ {
			switch args[i] {
			case "--project-root":
				if i+1 >= len(args) {
					fmt.Fprintln(os.Stderr, "ctxcop: --project-root requires a value")
					return 2
				}
				i++
				root = args[i]
			default:
				fmt.Fprintf(os.Stderr, "ctxcop: unknown preflight flag %q\n", args[i])
				return 2
			}
		}
		if err := aider.Preflight(root, os.Stderr); err != nil {
			fmt.Fprintf(os.Stderr, "ctxcop: aider preflight error: %v\n", err)
		}
		return 0
	default:
		fmt.Fprintf(os.Stderr, "ctxcop: unknown aider hook event %q\n", args[0])
		return 0
	}
}

// cmdHookOpenCode routes `ctxcop hook opencode <event>` — invoked by the
// TS plugin. Two events: tool-execute-before (block exfil-class tools
// with credential-shape args) and tool-execute-after (redact tool output
// strings). See docs/harnesses.md.
func cmdHookOpenCode(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "ctxcop: hook opencode requires an event name (tool-execute-before | tool-execute-after)")
		return 0
	}
	var err error
	switch args[0] {
	case "tool-execute-before":
		err = opencode.ToolExecuteBefore(os.Stdin, os.Stdout)
	case "tool-execute-after":
		err = opencode.ToolExecuteAfter(os.Stdin, os.Stdout)
	default:
		fmt.Fprintf(os.Stderr, "ctxcop: unknown opencode hook event %q\n", args[0])
		return 0
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "ctxcop: opencode hook error: %v\n", err)
	}
	return 0
}

// resolveVersion prefers the linker-injected version; falls back to
// debug.ReadBuildInfo (covers `go install …@vX.Y.Z`). Dev builds → "(devel)".
func resolveVersion() string {
	if version != "" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
		return info.Main.Version
	}
	return "(unknown)"
}

func cmdRules(args []string) int {
	if len(args) == 0 || args[0] != "list" {
		fmt.Fprintln(os.Stderr, "ctxcop: usage: ctxcop rules list")
		return 2
	}
	list, err := rules.List()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ctxcop: rules: %v\n", err)
		return 1
	}
	// Two-column output, source then rule id, with a header.
	fmt.Printf("%-20s %-45s %s\n", "SOURCE", "RULE ID", "STATE")
	for _, r := range list {
		state := "active"
		if r.Disabled {
			state = "disabled"
		}
		if r.Overridden {
			state += fmt.Sprintf(" (overridden from %s)", r.OverriddenFrom)
		}
		src := string(r.Source)
		if r.SourcePath != "" {
			src = fmt.Sprintf("%s:%s", r.Source, shortPath(r.SourcePath))
		}
		fmt.Printf("%-20s %-45s %s\n", src, r.ID, state)
	}
	return 0
}

// cmdAudit dispatches `ctxcop audit <subcmd>`. Today: verify.
func cmdAudit(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "ctxcop: audit requires a subcommand (verify)")
		return 2
	}
	switch args[0] {
	case "verify":
		return cmdAuditVerify(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "ctxcop: unknown audit subcommand %q (expected: verify)\n", args[0])
		return 2
	}
}

// cmdAuditVerify walks the audit log and reports tampered or
// reordered entries by line number. Path comes from --log <path>
// (or -l) or $CTXCOP_AUDIT_LOG; the flag wins on conflict.
func cmdAuditVerify(args []string) int {
	path := os.Getenv("CTXCOP_AUDIT_LOG")
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--log" || a == "-l":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "ctxcop: --log requires a value")
				return 2
			}
			i++
			path = args[i]
		case strings.HasPrefix(a, "--log="):
			path = a[len("--log="):]
		default:
			fmt.Fprintf(os.Stderr, "ctxcop: unknown flag %q (expected --log <path>)\n", a)
			return 2
		}
	}
	if path == "" {
		fmt.Fprintln(os.Stderr, "ctxcop: --log <path> or CTXCOP_AUDIT_LOG required")
		return 2
	}
	res, err := audit.Verify(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ctxcop: verify %s: %v\n", path, err)
		return 1
	}
	fmt.Printf("ctxcop audit verify %s\n", path)
	fmt.Printf("  entries:  %d\n", res.TotalEntries)
	fmt.Printf("  verified: %d\n", res.Verified)
	if res.Legacy > 0 {
		fmt.Printf("  legacy:   %d (unchained; predate the audit-chain feature)\n", res.Legacy)
	}
	if res.Ok() {
		fmt.Println("OK: chain intact")
		return 0
	}
	noun := "entries"
	if len(res.Broken) == 1 {
		noun = "entry"
	}
	fmt.Printf("FAIL: %d broken %s\n", len(res.Broken), noun)
	for _, b := range res.Broken {
		fmt.Printf("  line %d [%s]: %s\n", b.Line, b.Kind, b.Detail)
	}
	return 1
}

// shortPath returns the basename for long paths to keep tables readable.
func shortPath(p string) string {
	if len(p) <= 30 {
		return p
	}
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return ".../" + p[i+1:]
		}
	}
	return p
}

func cmdPause(args []string) int {
	dur := ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--for":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "ctxcop: --for requires a duration (e.g. 10m, 2h)")
				return 2
			}
			i++
			dur = args[i]
		default:
			fmt.Fprintf(os.Stderr, "ctxcop: unknown pause flag %q\n", args[i])
			return 2
		}
	}
	if err := pause.Pause(dur, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "ctxcop: pause: %v\n", err)
		return 1
	}
	return 0
}

func cmdResume() int {
	if err := pause.Resume(os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "ctxcop: resume: %v\n", err)
		return 1
	}
	return 0
}

func cmdStatus() int {
	if err := pause.Status(os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "ctxcop: status: %v\n", err)
		return 1
	}
	return 0
}

func cmdInstall(args []string) int {
	// Normalize `--key=value` to `--key value` so both styles work
	// (the brew-installed binary tends to get invoked from people's
	// shell scripts where `--harness=codex` is the more natural form).
	args = normalizeFlags(args)
	scope := claudecode.ScopeUser
	harnessFilter := "" // empty = autodetect; explicit values: claude-code, codex
	autoYes := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--scope":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "ctxcop: --scope requires a value")
				return 2
			}
			i++
			switch args[i] {
			case "user":
				scope = claudecode.ScopeUser
			case "project":
				scope = claudecode.ScopeProject
			default:
				fmt.Fprintf(os.Stderr, "ctxcop: invalid scope %q (use user|project)\n", args[i])
				return 2
			}
		case "--harness":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "ctxcop: --harness requires a value (claude-code | codex | auto)")
				return 2
			}
			i++
			harnessFilter = args[i]
		case "--yes", "-y":
			autoYes = true
		default:
			fmt.Fprintf(os.Stderr, "ctxcop: unknown install flag %q\n", args[i])
			return 2
		}
	}

	// Detect which harnesses are present, then optionally filter by
	// --harness=X. "auto" or empty = install to all detected.
	all := []string{"claude-code", "codex", "cursor", "pi", "opencode", "aider"}
	detected := map[string]bool{}
	for _, h := range all {
		detected[h] = harnessIsPresent(h, scope)
	}

	targets := []string{}
	switch harnessFilter {
	case "", "auto":
		for _, h := range all {
			if detected[h] {
				targets = append(targets, h)
			}
		}
	default:
		// explicit filter — install regardless of detection (user knows what they want)
		found := false
		for _, h := range all {
			if h == harnessFilter {
				targets = append(targets, h)
				found = true
				break
			}
		}
		if !found {
			fmt.Fprintf(os.Stderr, "ctxcop: unknown harness %q (supported: %v, auto)\n", harnessFilter, all)
			return 2
		}
	}

	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "ctxcop: no supported harness detected (looked for ~/.claude/, ~/.codex/, ~/.cursor/).")
		fmt.Fprintln(os.Stderr, "  Install Claude Code (https://docs.claude.com/en/docs/claude-code/installation),")
		fmt.Fprintln(os.Stderr, "  Codex CLI (https://github.com/openai/codex), or Cursor (https://cursor.com),")
		fmt.Fprintln(os.Stderr, "  then re-run `ctxcop install`.")
		fmt.Fprintln(os.Stderr, "  To install regardless of detection: `ctxcop install --harness=claude-code|codex|cursor|pi|opencode|aider`.")
		return 1
	}

	// Confirm-before-write. Autodetect installs mutate harness config
	// files across $HOME — show the user what we'd touch and require
	// affirmation. Skip when the user passed --yes, or when they
	// specified an explicit --harness=X (in which case they've already
	// committed to a target). Non-TTY stdin without --yes is treated
	// as a "no" rather than a silent yes — safer default for a
	// security tool.
	if !autoYes && (harnessFilter == "" || harnessFilter == "auto") {
		if !confirmInstall(scope, targets, detected, all) {
			fmt.Println("ctxcop: install aborted. No files were modified.")
			return 1
		}
	}

	for _, h := range targets {
		switch h {
		case "claude-code":
			if _, err := claudecode.Install(scope, os.Stdout); err != nil {
				fmt.Fprintf(os.Stderr, "ctxcop: claude-code install: %v\n", err)
				return 1
			}
		case "codex":
			if _, err := codex.Install(string(scope), os.Stdout); err != nil {
				fmt.Fprintf(os.Stderr, "ctxcop: codex install: %v\n", err)
				return 1
			}
		case "cursor":
			if _, err := cursor.Install(string(scope), os.Stdout); err != nil {
				fmt.Fprintf(os.Stderr, "ctxcop: cursor install: %v\n", err)
				return 1
			}
		case "pi":
			if _, err := pi.Install(string(scope), os.Stdout); err != nil {
				fmt.Fprintf(os.Stderr, "ctxcop: pi install: %v\n", err)
				return 1
			}
		case "opencode":
			if _, err := opencode.Install(string(scope), os.Stdout); err != nil {
				fmt.Fprintf(os.Stderr, "ctxcop: opencode install: %v\n", err)
				return 1
			}
		case "aider":
			if _, err := aider.Install(string(scope), os.Stdout); err != nil {
				fmt.Fprintf(os.Stderr, "ctxcop: aider install: %v\n", err)
				return 1
			}
		}
	}

	// "Also supported" hint — surface the harnesses we didn't write to
	// so engineers know what's available if they later install another
	// agent harness. Reads as a feature discovery, not a nag.
	if harnessFilter == "" || harnessFilter == "auto" {
		missing := []string{}
		for _, h := range all {
			if !detected[h] {
				missing = append(missing, h)
			}
		}
		if len(missing) > 0 {
			fmt.Println()
			fmt.Println("ctxcop also supports the following harnesses (not currently installed):")
			for _, h := range missing {
				fmt.Printf("  - %s — %s. After installing, re-run `ctxcop install` to wire hooks.\n",
					h, harnessHint(h))
			}
		}
	}
	return 0
}

// confirmInstall prints the plan and prompts y/N. Non-TTY without
// --yes is fail-closed.
func confirmInstall(scope claudecode.Scope, targets []string, detected map[string]bool, all []string) bool {
	fmt.Println("ctxcop install (auto-detected) will write hooks to:")
	for _, h := range targets {
		path := installPathFor(h, scope)
		fmt.Printf("  + %-12s  %s\n", h, path)
	}
	missing := []string{}
	for _, h := range all {
		if !detected[h] {
			missing = append(missing, h)
		}
	}
	if len(missing) > 0 {
		fmt.Println()
		fmt.Println("Not detected (skipped):")
		for _, h := range missing {
			fmt.Printf("  - %-12s  %s\n", h, harnessHint(h))
		}
	}
	fmt.Println()
	fmt.Println("Notes:")
	fmt.Println("  - Existing non-ctxcop hooks and unrelated config keys are preserved.")
	fmt.Println("  - Re-running is idempotent.")
	fmt.Println("  - To install without prompting (e.g. in scripts): `ctxcop install --yes`.")
	fmt.Println()
	return promptYN("Proceed?")
}

// confirmUninstall is the symmetric prompt for uninstall.
func confirmUninstall(scope claudecode.Scope, targets []string) bool {
	fmt.Println("ctxcop uninstall will remove ctxcop hook entries from:")
	for _, h := range targets {
		path := installPathFor(h, scope)
		fmt.Printf("  - %-12s  %s\n", h, path)
	}
	fmt.Println()
	fmt.Println("Notes:")
	fmt.Println("  - Non-ctxcop hooks and unrelated config keys are preserved.")
	fmt.Println("  - Files with no ctxcop entries (or that don't exist) are no-ops.")
	fmt.Println("  - To remove without prompting: `ctxcop uninstall --yes`.")
	fmt.Println()
	return promptYN("Proceed?")
}

// installPathFor returns the settings path for a harness at a scope.
func installPathFor(harness string, scope claudecode.Scope) string {
	switch harness {
	case "claude-code":
		p, _ := claudecode.SettingsPath(scope)
		return p
	case "codex":
		p, _ := codex.SettingsPath(string(scope))
		return p
	case "cursor":
		p, _ := cursor.SettingsPath(string(scope))
		return p
	case "pi":
		p, _ := pi.SettingsPath(string(scope))
		return p
	case "opencode":
		p, _ := opencode.SettingsPath(string(scope))
		return p
	case "aider":
		p, _ := aider.SettingsPath(string(scope))
		return p
	}
	return "?"
}

// promptYN reads y/N from stdin. Non-TTY returns false without reading —
// scripted callers must pass --yes.
func promptYN(question string) bool {
	if !stdinIsTTY() {
		fmt.Fprintln(os.Stderr, "ctxcop: refusing to prompt for confirmation without an interactive terminal.")
		fmt.Fprintln(os.Stderr, "  Pass --yes to confirm non-interactively.")
		return false
	}
	fmt.Printf("%s [y/N] ", question)
	var resp string
	_, _ = fmt.Scanln(&resp)
	resp = strings.ToLower(strings.TrimSpace(resp))
	return resp == "y" || resp == "yes"
}

func stdinIsTTY() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// cmdUninstall removes ctxcop entries across harnesses. Default
// --harness=all matches the typical "remove ctxcop everywhere" intent.
// Idempotent.
func cmdUninstall(args []string) int {
	args = normalizeFlags(args)
	scope := claudecode.ScopeUser
	// "all" is the default: remove ctxcop from every harness present.
	// Engineers nuking ctxcop don't typically want a per-harness loop.
	harnessFilter := "all"
	autoYes := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--scope":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "ctxcop: --scope requires a value")
				return 2
			}
			i++
			switch args[i] {
			case "user":
				scope = claudecode.ScopeUser
			case "project":
				scope = claudecode.ScopeProject
			default:
				fmt.Fprintf(os.Stderr, "ctxcop: invalid scope %q (use user|project)\n", args[i])
				return 2
			}
		case "--harness":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "ctxcop: --harness requires a value (claude-code | codex | cursor | all)")
				return 2
			}
			i++
			harnessFilter = args[i]
		case "--yes", "-y":
			autoYes = true
		default:
			fmt.Fprintf(os.Stderr, "ctxcop: unknown uninstall flag %q\n", args[i])
			return 2
		}
	}

	all := []string{"claude-code", "codex", "cursor", "pi", "opencode", "aider"}
	targets := all
	if harnessFilter != "all" {
		found := false
		for _, h := range all {
			if h == harnessFilter {
				targets = []string{harnessFilter}
				found = true
				break
			}
		}
		if !found {
			fmt.Fprintf(os.Stderr, "ctxcop: unknown harness %q (supported: %v, all)\n", harnessFilter, all)
			return 2
		}
	}

	// Confirm-before-write for the default `--harness=all` case. An
	// explicit `--harness=X` is treated as already-confirmed (user typed
	// it). --yes bypasses regardless.
	if !autoYes && harnessFilter == "all" {
		if !confirmUninstall(scope, targets) {
			fmt.Println("ctxcop: uninstall aborted. No files were modified.")
			return 1
		}
	}

	totalRemoved := 0
	for _, h := range targets {
		var removed int
		var err error
		switch h {
		case "claude-code":
			_, removed, err = claudecode.Uninstall(scope, os.Stdout)
		case "codex":
			_, removed, err = codex.Uninstall(string(scope), os.Stdout)
		case "cursor":
			_, removed, err = cursor.Uninstall(string(scope), os.Stdout)
		case "pi":
			_, removed, err = pi.Uninstall(string(scope), os.Stdout)
		case "opencode":
			_, removed, err = opencode.Uninstall(string(scope), os.Stdout)
		case "aider":
			_, removed, err = aider.Uninstall(string(scope), os.Stdout)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "ctxcop: %s uninstall: %v\n", h, err)
			return 1
		}
		totalRemoved += removed
	}

	if totalRemoved == 0 {
		fmt.Fprintln(os.Stdout, "")
		fmt.Fprintln(os.Stdout, "ctxcop: nothing was removed (no ctxcop entries found across the scanned harnesses). If you also want to remove the binary itself, delete it from wherever you installed it (see `which ctxcop`).")
	} else {
		fmt.Fprintln(os.Stdout, "")
		fmt.Fprintf(os.Stdout, "ctxcop: removed %d total hook entr%s. Delete the binary from wherever you installed it (see `which ctxcop`) to fully remove ctxcop.\n",
			totalRemoved, map[bool]string{true: "y", false: "ies"}[totalRemoved == 1])
	}
	return 0
}

// harnessIsPresent checks for the harness's settings dir at the scope.
func harnessIsPresent(harness string, scope claudecode.Scope) bool {
	// OpenCode's user-scope config lives at ~/.config/opencode/, not
	// ~/.opencode/, so the dir-under-home shorthand below doesn't apply.
	if harness == "opencode" {
		return opencode.IsPresent(string(scope))
	}
	// Aider's config is a single file (~/.aider.conf.yml or
	// ./.aider.conf.yml), not a dir. Detection reduces to a file stat
	// on the settings path itself.
	if harness == "aider" {
		p, err := aider.SettingsPath(string(scope))
		if err != nil {
			return false
		}
		_, err = os.Stat(p)
		return err == nil
	}
	var dir string
	switch harness {
	case "claude-code":
		dir = ".claude"
	case "codex":
		dir = ".codex"
	case "cursor":
		dir = ".cursor"
	case "pi":
		dir = ".pi"
	default:
		return false
	}
	var base string
	switch scope {
	case claudecode.ScopeUser:
		h, err := os.UserHomeDir()
		if err != nil {
			return false
		}
		base = h
	case claudecode.ScopeProject:
		cwd, err := os.Getwd()
		if err != nil {
			return false
		}
		base = cwd
	}
	_, err := os.Stat(base + "/" + dir)
	return err == nil
}

// normalizeFlags splits `--key=value` into two argv entries.
func normalizeFlags(args []string) []string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		if len(a) > 2 && a[0] == '-' && a[1] == '-' {
			if eq := indexByte(a, '='); eq > 0 {
				out = append(out, a[:eq], a[eq+1:])
				continue
			}
		}
		out = append(out, a)
	}
	return out
}

func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

func harnessHint(harness string) string {
	switch harness {
	case "claude-code":
		return "Anthropic Claude Code (https://docs.claude.com/en/docs/claude-code)"
	case "codex":
		return "OpenAI Codex CLI (https://github.com/openai/codex)"
	case "cursor":
		return "Cursor (https://cursor.com)"
	case "pi":
		return "pi.dev (https://pi.dev)"
	case "opencode":
		return "OpenCode (https://opencode.ai)"
	case "aider":
		return "Aider (https://aider.chat)"
	}
	return harness
}
