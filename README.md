<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="./webflow.svg">
    <img alt="Webflow" src="./webflow.svg" width="300">
  </picture>
</div>

# ctxcop

Keep secrets out of AI coding agents' context windows.
Supports [Claude Code](https://claude.com/claude-code),
[Codex CLI](https://github.com/openai/codex),
[Cursor](https://cursor.com), [Pi](https://pi.dev),
[OpenCode](https://opencode.ai), and [Aider](https://aider.chat)
(narrower coverage — see [docs/harnesses.md](docs/harnesses.md#aider)).

When the agent runs a Bash tool call:

```
Agent → Bash:  aws sts get-session-token
```

what reaches the model (after ctxcop's PreToolUse hook):

```
{
    "Credentials": {
        "AccessKeyId":     "<REDACTED:ctxcop-aws-access-key:OLIA>",
        "SecretAccessKey": "<REDACTED:aws-secret-key:fA31>",
        "SessionToken":    "<REDACTED:ctxcop-aws-session-token:7g8K>",
        "Expiration":      "2026-05-21T22:17:48Z"
    }
}
[ctxcop] redacted 3 secret(s) before this output reached the model.
```

Your own interactive shell is untouched. ctxcop only intercepts the
tool calls the agent makes through its harness.

ctxcop hooks into each harness's lifecycle events where a credential
might enter (or exit) the conversation and applies the right defense:
rewrite the call so the secret never reaches the model, deny it with
actionable retry guidance, or warn after the fact when neither is
possible. Detection uses [betterleaks](https://github.com/betterleaks/betterleaks)
(gitleaks' successor) plus an embedded high-confidence ruleset, with
recursive base64/hex/percent/unicode decoding and user/project
overlays.

---

## Install

Build from source for now — prebuilt binary releases are on hold until
macOS Developer ID codesigning + notarization are wired into the release
pipeline (Gatekeeper rejects the ad-hoc-signed binaries a plain `go build`
produces once they've been through a download/quarantine flow; a locally
built binary isn't affected).

```sh
# 1. go install.
go install github.com/webflow/ctxcop/cmd/ctxcop@latest

# 2. From source.
git clone https://github.com/webflow/ctxcop && cd ctxcop
go build -o /usr/local/bin/ctxcop ./cmd/ctxcop
```

## Wire it up

```sh
ctxcop install                       # autodetect ~/.claude, ~/.codex, ~/.cursor, ~/.pi, ~/.config/opencode, ~/.aider.conf.yml; prompt before writing
ctxcop install --harness=cursor      # one harness only; skips prompt
ctxcop install --harness=aider       # aider integration is static-config; see docs/harnesses.md#aider
ctxcop install --yes                 # autodetect, skip prompt (CI)
```

Idempotent — prior ctxcop entries are replaced cleanly; unrelated
hooks, model settings, and MCP config are preserved. A fresh harness
session picks up the hooks; the first SessionStart additionalContext
block primes the agent.

## Verify

```sh
$ printf 'AWS_ACCESS_KEY_ID=%sLALEMEL33243OLIA\n' AKIA | ctxcop scan
AWS_ACCESS_KEY_ID=<REDACTED:ctxcop-aws-access-key:OLIA>
```

## Uninstall

```sh
ctxcop uninstall                     # prompts; removes from every detected harness
ctxcop uninstall --harness=cursor    # one harness
```

Run `ctxcop uninstall` before removing the binary itself. Otherwise each
harness exec's a path that no longer exists. Most fail open, but you'll
see log noise.

---

## Configuration

Runtime behavior via environment variables; install-time behavior via
flags. Nothing retained on disk by default.

### Runtime env vars

| Variable | Default | Purpose |
| --- | --- | --- |
| `CTXCOP_AUDIT_LOG` | unset | Path to an append-only JSONL log. Unset = no logging. One line per event: `{ts, tool, action, rules, count, field}`. Mode 0600. |
| `CTXCOP_RULES` | unset | Path to an extra TOML rule file. |
| `CTXCOP_DISABLE_RULES` | unset | Comma-separated rule IDs to remove from the composed ruleset. |
| `CTXCOP_POSTTOOLUSE` | empty | Set to `off` to disable Claude Code's PostToolUse warning hook. |
| `CTXCOP_POSTTOOLUSE_ALLOW` | unset | Comma-separated tool-name globs (only `*` wildcard) whose responses should not trigger Claude Code's PostToolUse notice. The audit log records `warned-suppressed` instead. |
| `CTXCOP_SKIP_PATHS` | unset | Comma-separated glob list of paths where Read/Write/Edit/NotebookEdit hooks should not scan. Adds to baked-in defaults (`testdata/`, `fixtures/`, `*_test.*`, etc.). |
| `CTXCOP_DEV` | empty | Set to `warn` to downgrade Write/Edit/WebFetch/MCP blocks to allow + warning. UserPromptSubmit and Bash/Read paths unaffected. |

### Install-time flags

| Flag | Default | Purpose |
| --- | --- | --- |
| `--harness=auto\|claude-code\|codex\|cursor\|pi\|opencode\|aider\|all` | `auto` (install) / `all` (uninstall) | Which harnesses to write to. |
| `--scope=user\|project` | `user` | `user` writes to `$HOME/.<harness>/`. `project` writes to `./.<harness>/` for repo-local hook configs. |
| `--yes` / `-y` | off | Skip the confirm-before-write prompt. Required for non-TTY invocations — without it, ctxcop fails closed rather than silently confirming a piped "yes". |

---

## Documentation

- [docs/harnesses.md](docs/harnesses.md) — per-harness hook coverage and steering guidance
- [docs/detection.md](docs/detection.md) — rules, overlays, fixtures, project config
- [docs/hook-contracts.md](docs/hook-contracts.md) — JSON wire shapes per harness event
- [docs/architecture.md](docs/architecture.md) — code structure and invariants
- [docs/known-limits.md](docs/known-limits.md) — documented bypasses and gaps
- [docs/verify-reproducibility.md](docs/verify-reproducibility.md) — rebuild a tag from source and compare sha256
- [SECURITY.md](SECURITY.md) — vulnerability disclosure, embargo terms, build verification
- [THREATMODEL.md](THREATMODEL.md) — trust model, in-scope and out-of-scope threats
- [THIRD_PARTY_AUDIT.md](THIRD_PARTY_AUDIT.md) — dependency review log
- [CHANGELOG.md](CHANGELOG.md) — release notes
- [ROADMAP.md](ROADMAP.md) — planned work
- [testing/](testing/) — manual end-to-end fixtures for harness adapters

## Development

```sh
go test ./...
go vet ./...
go build -o ctxcop ./cmd/ctxcop
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for DCO sign-off, signed commits,
and pre-merge gates. Maintainer team is `@arr-wf` plus
`@webflow/infrastructure-security`; routing per
[.github/CODEOWNERS](.github/CODEOWNERS).

## License

MIT — see [LICENSE](LICENSE).

ctxcop is built on the [betterleaks](https://github.com/betterleaks/betterleaks)
secret-scanning engine (MIT, © Zachary Rice). Full third-party
attributions are in [NOTICES.md](NOTICES.md).

## Webflow Open Source

Webflow builds the visual development platform behind millions of
websites. We open source internal tools like ctxcop when we think
they're broadly useful beyond our own stack. Check out our other
projects at [github.com/webflow](https://github.com/webflow).
