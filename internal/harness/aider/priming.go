package aider

// primingMarkdown is the SessionStart-equivalent priming text for
// Aider. Aider has no SessionStart hook; it loads `read:` files as
// pinned context on every session start, so writing this to
// ~/.aider/ctxcop-priming.md and adding the path to `read:` gets us
// the same guarantee: every new session begins with the model having
// seen these conventions.
//
// Kept short (~130 tokens) because it rides in the model context for
// every turn, not just the first one — Aider re-reads pinned files
// per session but they persist across the whole conversation.
const primingMarkdown = "# ctxcop conventions (auto-injected)\n" +
	"\n" +
	"ctxcop is watching this Aider session. Its coverage is narrower than in\n" +
	"harnesses with a runtime hook lifecycle:\n" +
	"\n" +
	"- **Lint/test output**: redacted before it reaches your context, via a\n" +
	"  static wrap of `lint-cmd` / `test-cmd` in `.aider.conf.yml`. If you\n" +
	"  see a `<REDACTED:…>` placeholder in a lint/test failure, the value\n" +
	"  never entered your tokens.\n" +
	"- **Chat prompts and edit blocks**: Aider does not expose a\n" +
	"  UserPromptSubmit-equivalent, so a credential pasted into chat reaches\n" +
	"  your context and the transcript on disk unfiltered. Reference secrets\n" +
	"  abstractly (\"my production AWS access key\"), not literally.\n" +
	"- **LiteLLM round-trip**: no `before_provider_request`-style chokepoint\n" +
	"  exists in Aider today. If a secret appears in your context via any\n" +
	"  path ctxcop cannot intercept, treat it as compromised and rotate.\n" +
	"\n" +
	"Working conventions:\n" +
	"\n" +
	"- **In code you generate**: emit `os.Getenv(\"X\")` / `process.env.X` /\n" +
	"  `${ENV_VAR}` references, never literal credential values.\n" +
	"- **In shell suggestions**: export values in the user's shell first\n" +
	"  (`export TOKEN=…`), then use `$TOKEN` in the command you propose. The\n" +
	"  literal never enters your context.\n" +
	"- **Don't try to reverse a placeholder**: `<REDACTED:ctxcop-…:XXXX>`\n" +
	"  means ctxcop deliberately withheld the value. Piping it through\n" +
	"  `base64 -d` / `xxd` / `cat` will not recover the secret and is\n" +
	"  recorded in the audit log.\n"
