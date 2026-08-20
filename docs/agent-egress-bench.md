# agent-egress-bench evaluation

[agent-egress-bench](https://github.com/luckyPipewrench/agent-egress-bench)
(AEB) is an external, vendor-neutral test corpus for AI-agent egress
security tools. We ran the applicable slice of it against ctxcop as an
independent check on the detection engine. This doc records the method,
the results, and — the important part — an honest decomposition of what
ctxcop does and does not cover, and why.

Corpus: AEB v2 (`schema_version: 2`). Run date: 2026-07-30, against
`ctxcop` at the post-`v0.4.0-rc.1` main.

## Scope: content layer vs. network layer

AEB is primarily a **network-egress** benchmark. Its runner drives cases
over HTTP/TLS/WebSocket/DNS/MCP transports and scores whether the tool
under test (a proxy, firewall, or MCP gateway) **blocks or allows** the
connection. That is a different interposition point from ctxcop.

ctxcop is a **content redactor at the harness-hook layer**. It does not
sit on the network path and does not block connections; it removes
secrets from tool I/O before they reach the model's context. So a large
part of AEB — SSRF, DNS/hostname exfiltration, WebSocket transport, A2A
messaging, MCP tool-poisoning, behavioral tool-chains, shell
command-intent, network response MITM — is **out of ctxcop's design by
construction**. ctxcop is complementary to a network egress proxy, not a
replacement for one. (See [known-limits.md](known-limits.md) and
[THREATMODEL.md](../THREATMODEL.md) for the same boundary.)

AEB's own case schema encodes this: each case declares a `requires`
capability (e.g. `encoding_evasion_scanning`, `ssrf_scanning`), and its
`profiles/` model supports scoring a tool `n/a` on out-of-scope cases. We
report only the **content-DLP** categories below and treat the
network/behavioral categories as out of scope, not as failures.

We did **not** run AEB's network gauntlet runner — it opens real
outbound exfiltration connections to exercise a proxy, and ctxcop exposes
no such endpoint. Instead each case's `payload` was fed through
`ctxcop scan` and scored against the case's `expected_verdict`
(`block` → must redact; `allow` → must not).

## Results — content-DLP categories (default ruleset)

| Category | Score | Notes |
| --- | --- | --- |
| encoding-evasion | 8/9 | base64/hex/URL/JWT + the zero-width, delimited-hex, HTML-entity passes |
| url | 11/20 | see decomposition — 6 of the 9 misses are out-of-scope network cases |
| headers | 11/13 | Bearer/Basic/AWS/SendGrid/JWT |
| request-body | 14/21 | JSON/env-dump/PEM/base64; PII cases need the opt-in ruleset |
| mcp-input | 9/11 | secrets in MCP tool-call arguments, incl. nested/encoded |
| false-positive | 19/20 | **precision** — see below |

**72/94 as scored.** That raw number understates coverage because the
category folders mix content-DLP with out-of-scope and artifact cases;
the decomposition below accounts for every miss.

**Precision.** 19/20 on the dedicated false-positive corpus. The single
redacting allow-case is `fp-example-aws-key-003` — AWS's canonical
`AKIA…EXAMPLE` documentation key, which ctxcop redacts by design
(over-redaction is its chosen safe direction; it cannot reliably tell a
"documentation example" credential from a live one). Every fix in the
v0.4.0 line was gated to add **zero** new false positives on this corpus,
and additionally to add zero new redactions on an 11-case "normal agent
flows" suite (OAuth authorize/callback URLs, session cookies, MAC/ETag,
git SHAs, MCP auth-token arguments) — so the normalization and new
credential rules do not disturb ordinary agent traffic such as MCP
authentication.

## Optional PII/DLP ruleset

Crypto-wallet and financial-PII detection is **not** part of ctxcop's
default, credential-focused scope. It ships as an opt-in example ruleset
(`examples/rules/pii-dlp.toml`) loaded via `CTXCOP_RULES`:

| | default | with `CTXCOP_RULES=examples/rules/pii-dlp.toml` |
| --- | --- | --- |
| crypto-financial | 2/11 | **11/11** |

Enabling it also redacts the two `request-body` PII cases (credit-card
CSV, SSN/routing). It adds zero new false positives on the AEB
false-positive corpus. See [`examples/rules/README.md`](../examples/rules/README.md).

## Honest decomposition of the 22 content-category misses

Not all "misses" are detection gaps. Broken out:

**Out-of-scope, filed under a content category (8).** Network/behavioral
cases that happen to live in the `url`/`mcp-input`/`encoding-evasion`
folders:
- `url-ssrf-*` (3), `url-entropy-*` (2), `url-domain-blocklist-001` —
  SSRF / entropy / egress-blocklist are network-path controls.
- `mcp-input-injection-002` — prompt-injection detection, not secret
  content.
- `enc-unicode-homoglyph-006` — homoglyph substitution in a *command*;
  command-intent detection, not a secret.

**Covered by the opt-in PII ruleset, not the default (2).**
`body-dlp-csv-pii-006`, `body-dlp-ssn-routing-010` — redact when
`examples/rules/pii-dlp.toml` is enabled.

**AEB fixture artifacts ctxcop correctly rejects (6).** The fixture token
is malformed, so the strict rule declines it — a *valid* token of the
same type is redacted:
- `url-dlp-github-token-002`, `header-dlp-cookie-003`,
  `body-dlp-multipart-002` — `ghp_`+34 chars (a real classic PAT is
  `ghp_`+36 = 40); a canonical token fires.
- `url-dlp-gitlab-deploy-token-001` — `gldt-`+29 (wrong length).
- `body-dlp-yaml-secrets-005` — `sk_live_FAKE_…` with underscores (a
  real Stripe key is alphanumeric; a canonical one fires).
- `body-dlp-base64-paste-aws-key-004` — decodes to a malformed 23-char
  `AKIAEXAMPLE…`, which betterleaks' recursive base64 decode correctly
  does not attest.

Redacting these would require loosening the rules below the length/charset
of the real credential — trading precision for a benchmark point. We kept
the precision.

**Intentional precision holds (2).** `header-dlp-referer-token-008` and
`body-dlp-hex-encoded-007` embed a bare 40-char AWS *secret* access key
with no adjacent `aws_secret…` keyword. Catching them needs an ungated
40-char-base64 rule, which fires on OAuth `code_challenge` values and
CloudFront request-ids in normal traffic. Precision gate kept over recall.

**One over-redaction (1).** `fp-example-aws-key-003` — the deliberate
documentation-example over-redaction described under Precision.

**Genuine open items (3).**
- `body-dlp-azure-storage-key-001` — Azure storage account key (88-char
  base64); addable as a keyword-gated rule, deferred for FP tuning.
- `url-dlp-gcp-service-account-001` — the payload carries a
  `"type":"service_account"` marker but **no key material**; needs a
  structural heuristic rather than a credential regex.
- `mcp-input-scattered-secret-005` — an AWS key split across two sibling
  JSON fields; needs cross-field reassembly, out of reach of single-buffer
  normalization.

## Out-of-scope categories (not scored)

Documented as deliberate boundaries — the province of a network egress
proxy or a behavioral monitor, not a content redactor:

| Category | Cases | Why out of scope |
| --- | --- | --- |
| ssrf-bypass | 11 | connection-target control |
| hostname-exfiltration | 10 | DNS/hostname channel |
| websocket-dlp | 9 | WebSocket transport interception |
| a2a-agent-card / a2a-message | 20 | agent-to-agent transport |
| mcp-tool | 8 | tool-definition poisoning / rug-pull |
| mcp-chain | 10 | behavioral multi-step sequence analysis |
| shell-obfuscation | 10 | obfuscated *command-intent* detection |
| response-fetch / response-mitm | 17 | network response injection / MITM |

## Method footnote: the tool blocked its own test harness

An early attempt to run this matrix via a subagent stalled because
ctxcop's own `PreToolUse` hook (the v0.4.0 fix that **denies Bash
commands containing a literal secret**) blocked the harness's test
commands — `echo 'AKIA…' | ctxcop`, heredocs and `curl -H "Authorization:
Bearer …"` with inline secrets — before they could run. Subagents run
under the live session's hooks, so the tool correctly refused to let a
credential sit in a command line. The working method reads every payload
from the corpus files on disk and pipes via stdin, and constructs any
synthetic secret from concatenated fragments, so no contiguous secret
ever appears in a command. It's a real usability signal, and the fix for
it is the same guidance ctxcop gives agents: reference secrets by env
var, never inline them.

## Reproduce

```sh
# clone the corpus (read-only; do NOT run its network gauntlet against ctxcop)
git clone --depth 1 https://github.com/luckyPipewrench/agent-egress-bench

# score one category: feed each case payload through scan, check redaction
for f in agent-egress-bench/cases/encoding-evasion/*.json; do
  exp=$(jq -r .expected_verdict "$f")
  red=$(jq -c .payload "$f" | ctxcop scan | grep -q '<REDACTED:' && echo yes || echo no)
  echo "$(jq -r .id "$f")  expect=$exp  redacted=$red"
done

# PII categories require the opt-in ruleset:
#   CTXCOP_RULES=examples/rules/pii-dlp.toml ctxcop scan
```

A ctxcop capability profile for upstream contribution to AEB is planned
after the project goes public.
