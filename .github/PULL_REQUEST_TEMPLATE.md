<!--
Thanks for the contribution. The checkboxes aren't busywork — each one
catches a class of regression we've shipped before. SECURITY.md +
THREATMODEL.md + CONTRIBUTING.md cover the policy details.
-->

## Summary

<!-- One or two sentences on what this PR changes and why. -->

## Test plan

<!--
Concrete commands or scenarios you ran. "go test ./..." is good; "go
test -race -count=1 ./... and manually exercised cursor pretool with the
attached JSON" is better. CI runs the suite plus lint/vuln-check/
self-scan, but local reasoning about coverage is still expected.
-->

- [ ] `go test -race -count=1 ./...` passes
- [ ] `gofmt -w .` is clean
- [ ] `go vet ./...` is clean

## Security checklist

<!--
Skip a box if it genuinely doesn't apply — but say so in a comment so a
reviewer can confirm. Silent skips on these slowed reviews on prior PRs.
-->

- [ ] This PR does not change detection or bypass surface.
  - If it DOES: **THREATMODEL.md is updated** in the same PR.
- [ ] No new third-party Go dependency. (If yes: THIRD_PARTY_AUDIT.md
  entry + `@webflow/infrastructure-security` review.)
- [ ] No new third-party GitHub Action. (If yes: ACTION_PIN_POLICY.md
  followed, action-allowlist.txt updated, SHA-pinned with `# vX.Y.Z`
  comment.)
- [ ] No literal credential-shape strings in source outside fixture
  paths covered by the skip-list. (Run `./ctxcop scan` against any
  modified files if uncertain.)
- [ ] Audit-log entries (`internal/audit.Log`) cover any new
  decision path that blocks, redacts, or warns.

## Reviewer notes

<!--
Anything reviewers should know before reading the diff: design
trade-offs, files where context lives, related issues, planned
follow-ups. Helps reviewers spend their attention where it matters.
-->
