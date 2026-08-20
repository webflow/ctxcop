# Example rulesets

Optional, opt-in ctxcop rulesets. They are **not** loaded by default — ctxcop's
built-in pack deliberately stays focused on machine credentials (API keys,
tokens, session material). The files here cover broader classes that some
users want but that carry more false-positive risk.

## `pii-dlp.toml` — crypto-wallet + financial PII

Adds detectors for wallet identifiers and financial PII that the default pack
does not target:

- Bitcoin P2PKH (`1…`) and Bech32 (`bc1…`) addresses
- Ethereum address (`0x` + 40 hex) and raw secp256k1 private key (64 hex)
- Extended public key (`xpub…`) and WIF private key
- BIP-39 mnemonic seed phrases (12–24 words)
- Payment card numbers, IBAN, US SSN, bank routing / account numbers

### Enable it

Point the existing `CTXCOP_RULES` overlay at the file — no code changes, no
rebuild:

```sh
CTXCOP_RULES=/path/to/ctxcop/examples/rules/pii-dlp.toml ctxcop scan
```

Set it in your shell profile (or your agent harness's env) to keep it on:

```sh
export CTXCOP_RULES="$HOME/src/ctxcop/examples/rules/pii-dlp.toml"
```

Confirm it loaded:

```sh
CTXCOP_RULES=/path/to/ctxcop/examples/rules/pii-dlp.toml ctxcop rules list | grep pii-
```

### Caveat

PII/DLP rules are inherently more false-positive-prone than credential
prefixes — a 16-digit number or a run of lowercase words has no unique
signature the way `ghp_…` does. This pack leans on keyword prefilters, format
and length anchors, and a stopword filter for seed phrases to keep noise low,
but expect the occasional over-redaction and tune the rules to your data.
