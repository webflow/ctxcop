# Contributing to ctxcop

Thank you for your interest! ctxcop is a defensive security tool, so the
contribution process has a few more checkpoints than a typical Go CLI.
Most of them exist to keep the supply chain tight; none are designed to
discourage contributions.

## Quick start

```bash
git clone git@github.com:webflow/ctxcop.git
cd ctxcop
go build ./cmd/ctxcop
go test ./...
```

The test suite runs in under 20 seconds. `go test -race ./...` is the
default we run in CI; please run it locally before opening a PR.

## What we welcome

- Bug fixes with regression tests.
- New detection rules for credential formats not currently covered.
  Open an issue first to discuss the pattern; the embedded ruleset has
  a high-confidence bar (see `internal/rules/embedded/ctxcop.toml`).
- New harness adapter support, ideally with comprehensive tests of the
  hook event JSON shapes — Claude Code's UserPromptSubmit shape bug
  (silent-success-with-wrong-shape) is a cautionary tale and pattern-
  matched in the existing tests.
- Documentation improvements, especially clarifying examples for the
  threat model and the install/uninstall flows.
- Bots - are welcome here, but please use them responsibly.

## What we won't merge

- Changes that loosen the redaction guarantees without an explicit
  decision (e.g., disabling the ANSI-interleave fallback, dropping the
  pause-banner).
- New third-party GitHub Actions or dependencies without
  `@webflow/infrastructure-security` review and an entry in
  `THIRD_PARTY_AUDIT.md`. See `.github/ACTION_PIN_POLICY.md`.
- Anything that adds a new credential / network endpoint / runtime
  dependency the binary phones home to. ctxcop is intentionally an
  offline tool.

## Before you open a PR

Run, in this order:

```bash
gofmt -w .
go vet ./...
go test -race -count=1 ./...
go build ./cmd/ctxcop && ./ctxcop --version
```

CI will run all of these plus linters (golangci-lint), govulncheck,
osv-scanner, gosec, license-audit, and a self-scan (ctxcop scanning its
own source for credential-shape leaks). PRs that fail any of these
won't be merged.

For changes to detection behavior or bypass surface, **update
`THREATMODEL.md`** as part of the same PR. The PR template includes
a checkbox to remind you.

## Sign-off and commit signing

We use the [Developer Certificate of Origin (DCO)](https://developercertificate.org/).
Every commit must be signed off with `git commit -s`, which adds a
`Signed-off-by: Your Name <your.email@example.com>` trailer attesting
that you have the right to submit the change under the project's
license.

Commits to `main` must also be cryptographically signed — the
`main-branch-protection` ruleset requires it. Either GPG or SSH-based
signing works; SSH-based is the lowest-friction option.

**Software SSH key (basic):**

```bash
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub
git config --global commit.gpgsign true
git config --global tag.gpgsign true
```

Add the same public key to your GitHub account's "SSH and GPG keys"
settings as a **Signing Key** (separately from any Authentication Key
entry — same key material, different role assignment).

**Hardware key (preferred — YubiKey 5+ or any FIDO2 token):**

macOS users will need Homebrew's OpenSSH because the Apple-bundled
build doesn't include FIDO middleware:

```bash
brew install openssh
$(brew --prefix)/bin/ssh-keygen -t ed25519-sk -O resident -O verify-required \
  -C "you@example.com (yubikey)" \
  -f ~/.ssh/id_ed25519_sk
git config --global gpg.format ssh
git config --global gpg.ssh.program $(brew --prefix)/bin/ssh-keygen
git config --global user.signingkey ~/.ssh/id_ed25519_sk.pub
git config --global commit.gpgsign true
git config --global tag.gpgsign true
```

Upload `~/.ssh/id_ed25519_sk.pub` to GitHub as a Signing Key. Each
commit will prompt for a YubiKey touch (and PIN if you used
`verify-required`).

**Local verification** (so `git log --show-signature` actually verifies):

```bash
mkdir -p ~/.config/git
PUB="$(awk '{print $1, $2}' ~/.ssh/id_ed25519_sk.pub)"   # adjust filename
echo "you@example.com $PUB" >> ~/.config/git/allowed_signers
git config --global gpg.ssh.allowedSignersFile ~/.config/git/allowed_signers
```

## Maintainer onboarding

The maintainer pool is intentionally small. New maintainers are added
after sustained quality contributions and a second-sign-off from an
existing maintainer. Requirements:

- Current Webflow employment. ctxcop is a Webflow-maintained project;
  external maintainership will be revisited once the contributor
  pool stabilizes.
- Hardware-key 2FA enforced on your GitHub account.
- Signed-commit key added to the repo's `allowed-signers` list.
- Membership in the `@webflow/ctxcop-maintainers` GitHub team.
- `release-managers` membership (the team allowed to push `v*` tags)
  is a separate, higher trust level — it requires a third sign-off
  from an existing release-manager. Tag-pushing is the chokepoint of
  the signed-release pipeline.

## Reporting vulnerabilities

Do NOT open a public issue for security bugs. See
[SECURITY.md](SECURITY.md) for the GitHub Private Security Advisory
flow and the `security@webflow.com` backup channel.

## Code style

- Standard Go: `gofmt -s`, idiomatic naming, no premature abstractions.
- Comments explain *why*, not *what*. The codebase already follows
  this pattern; new code should match the tone.
- One concern per PR. Bundle related changes; split unrelated ones.
- No new third-party dependencies without justification in the PR
  description. We prefer adding ~20 lines to internal code over
  pulling in a 500-line library.

## Testing

- Every redaction-layer change needs a test that asserts the secret
  bytes don't survive to the output AND that surrounding content does.
  The pattern is in `internal/redact/redact_test.go`.
- Every harness handler change needs a test that asserts the JSON
  output shape (`hookSpecificOutput` vs flat, top-level `decision`
  vs nested, etc.). Wrong-shape failures are silent failures, which is
  the worst class for a security control.
- Run with `-race`. ctxcop hooks fire on every tool call across
  potentially-concurrent agent loops; data races at the wrong moment
  cause subtle leaks.

## Code of Conduct

We follow the [Contributor Covenant v2.1](CODE_OF_CONDUCT.md).
Enforcement contact is `security@webflow.com` (we reuse this address
rather than proliferate inboxes).

## License

By contributing, you agree that your contributions will be licensed
under the MIT License (see [LICENSE](LICENSE)).
