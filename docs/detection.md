# Detection

The redactor composes rules from four sources, in load order. Later
sources override earlier rules with the same ID; the final ruleset is
what every hook scans.

1. **betterleaks defaults** — ~270 rules, the upstream betterleaks v1.2
   ruleset (a gitleaks v8 successor) embedded in the binary. Includes
   built-in recursive codec decoding (base64/hex/percent/unicode) so
   secrets that were encoded before they reached the tool output are
   still caught.
2. **ctxcop embedded pack** — eight high-confidence single-purpose
   patterns shipped in the binary. Same shape as gitleaks rules but
   tuned for the CLI-output threat model: where gitleaks requires a
   `\b` boundary (so credentials glued to surrounding text by tools
   that elide whitespace get missed), the ctxcop rules drop the
   boundary. Over-redaction in tool output is safe; under-redaction
   leaks.

   | Rule ID | Covers |
   | --- | --- |
   | `ctxcop-aws-access-key` | AKIA / ASIA / A3T / ABIA / ACCA |
   | `ctxcop-aws-session-token` | FwoG / FwoD / IQoJ / IQoD / FQoG |
   | `ctxcop-github-pat-classic` | `ghp_` |
   | `ctxcop-github-pat-finegrained` | `github_pat_` |
   | `ctxcop-github-app-token` | `gho_` / `ghu_` / `ghs_` / `ghr_` |
   | `ctxcop-gitlab-pat` | `glpat-` |
   | `ctxcop-slack-token` | `xox[bpoars]-` |
   | `ctxcop-stripe-secret-key` | `(sk\|rk)_(live\|test)_` |

3. **`~/.ctxcop/*.toml`** — every `.toml` file in the user rules dir,
   loaded in alphabetical order. Drop org-specific credential patterns
   here — in-house service token prefixes, customer-ID formats,
   internal API key shapes.
4. **`$CTXCOP_RULES`** — a single explicit TOML path. Useful for
   one-off or per-machine extras.

The schema is gitleaks' TOML — `[[rules]]` blocks with `id`,
`description`, `regex`, `keywords`, `entropy`, `allowlists`.

`ctxcop rules list` prints every active rule with provenance:

```
SOURCE                       RULE ID                                STATE
upstream-default             aws-access-token                       active
ctxcop-embedded:<embedded>   ctxcop-aws-access-key                  active
user-file:.../internal.toml  acme-internal-service-token            active
```

To silence a noisy rule without editing files:

```sh
export CTXCOP_DISABLE_RULES='some-rule-id,another-id'
```

If a rule TOML contains a bad regex (e.g. a repeat count Go's RE2
rejects), the loader recovers and falls back to upstream defaults with
a stderr warning. A single typo'd rule cannot block tool calls.

## Working with fixtures

ctxcop leaves intentional fixture work alone:

- **Path skip-list.** Read/Write/Edit on paths matching `testdata/**`,
  `fixtures/**`, `*_test.*`, `*.test.*`, `*.spec.*`, `*.golden`,
  `*.fixture.*`, `__fixtures__/**`, `cassettes/**` is passthrough.
  Extend with `CTXCOP_SKIP_PATHS` or a project `.ctxcop.toml`'s
  `skip_paths`.
- **Inline annotation.** Suffix any line with `ctxcop:fixture` (or
  `ctxcop:allow`, or the legacy `gitleaks:allow`) and that line is
  excluded from detection.
- **Dev mode.** `CTXCOP_DEV=warn` flips Write/Edit/WebFetch/MCP blocks
  into allow + warning while iterating on fixtures. UserPromptSubmit
  and Bash/Read rewrites still apply.
- **Pause.** `ctxcop pause --for 30m` suspends all hook activity
  (passthrough) until the timer expires. `ctxcop resume` ends it
  early; `ctxcop status` reports state.

## Project config (`.ctxcop.toml`)

Walking up from cwd (max 8 levels) ctxcop looks for `.ctxcop.toml`.
Schema is gitleaks TOML plus one extra:

```toml
# Adds to the skip-list for Read/Write/Edit scans.
skip_paths = ["my-fixtures/**", "*.snapshot", "scripts/seed-*.sh"]

[[rules]]
id = "acme-internal-token"
description = "Acme internal service token"
regex = '''(ACME_[A-Z0-9]{20})'''
keywords = ["acme_"]
```

Standard gitleaks `[[rules.allowlists]]` work too, so a project can
declare repository-specific patterns to allow without per-line
annotations.
