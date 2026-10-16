package rules

import "testing"

// Redis AUTH coverage (ctxcop-redis-auth-* rules). Ported from
// webflow/secrets-scrubber, which was built around a real Redis key leak
// into an AI session. Positive shapes are the leak forms; negative shapes
// are secrets-scrubber's own false-positive suite plus the gates added in
// the port. Every literal is split via join() so no contiguous
// credential-shaped string sits in this file.
func TestRedisAuthRulesMatchAndAreGated(t *testing.T) {
	token := join("Zk3", "mQ9vLp2XwR7tY", "bN4cH8dF") // 24-char fake
	user := "svc"

	cases := []struct {
		name    string
		content string
		want    string // rule ID that must fire
		notWant string // rule ID that must NOT fire
	}{
		// Plain AUTH command line.
		{
			name:    "plain AUTH command in an error line",
			content: join("AbortError: AUTH ", token, " failed"),
			want:    "ctxcop-redis-auth-command",
		},
		{
			name:    "AUTH with ACL username",
			content: join("AUTH ", user, " ", token),
			want:    "ctxcop-redis-auth-command",
		},
		{
			// secrets-scrubber's prose gate: a status phrase after the
			// AUTH verb is not a password.
			name:    "prose after AUTH verb is left alone",
			content: "AUTH rotation-complete",
			notWant: "ctxcop-redis-auth-command",
		},
		{
			name:    "env-var reference value is left alone",
			content: "AUTH $REDIS_PASS",
			notWant: "ctxcop-redis-auth-command",
		},
		{
			name:    "process.env reference value is left alone",
			content: "password: process.env.REDIS_PASS",
			notWant: "ctxcop-redis-auth-command",
		},
		// Structured args / JSON (node-redis error form).
		{
			name:    "node-redis args array without user",
			content: join("args: [ 'AUTH', '", token, "' ]"),
			want:    "ctxcop-redis-auth-array",
		},
		{
			name:    "node-redis JSON array with user",
			content: join(`["AUTH","`, user, `","`, token, `"]`),
			want:    "ctxcop-redis-auth-array",
		},
		{
			name:    "pretty-printed JSON with newline between elements",
			content: join("[\"AUTH\",\n  \"", token, "\"]"),
			want:    "ctxcop-redis-auth-array",
		},
		{
			name:    "array value under 8-char floor is left alone",
			content: `["AUTH","svc","short"]`,
			notWant: "ctxcop-redis-auth-array",
		},
		{
			name:    "array process.env value is left alone",
			content: `["AUTH","svc","process.env.REDIS_PASS"]`,
			notWant: "ctxcop-redis-auth-array",
		},
		// RESP protocol dumps.
		{
			name:    "RESP dump, raw CRLF, no user",
			content: join("*2\r\n$4\r\nAUTH\r\n$24\r\n", token, "\r\n"),
			want:    "ctxcop-redis-auth-resp",
		},
		{
			name:    "RESP dump, raw CRLF, with ACL user",
			content: join("*3\r\n$4\r\nAUTH\r\n$3\r\n", user, "\r\n$24\r\n", token, "\r\n"),
			want:    "ctxcop-redis-auth-resp",
		},
		{
			name:    "RESP dump, escaped CRLF text form",
			content: join("*2\\r\\n$4\\r\\nAUTH\\r\\n$24\\r\\n", token, "\\r\\n"),
			want:    "ctxcop-redis-auth-resp",
		},
		{
			name:    "RESP dump, space-flattened, lowercase command",
			content: join("*2 $4 auth $24 ", token, " done"),
			want:    "ctxcop-redis-auth-resp",
		},
		{
			// Other RESP commands must stay untouched.
			name:    "RESP GET dump is left alone",
			content: "*2\r\n$3\r\nGET\r\n$24\r\nsome:cache:key:abc12345\r\n",
			notWant: "ctxcop-redis-auth-resp",
		},
		{
			// Port deviation from secrets-scrubber: the RESP rule requires
			// the *N array header, so headerless prose dollar-amounts near
			// the word auth do not redact.
			name:    "flattened AUTH without array header is left alone",
			content: join("$4 auth $24 ", token, " done"),
			notWant: "ctxcop-redis-auth-resp",
		},
		// redis-cli flags.
		{
			name:    "redis-cli -a with other flags",
			content: join("redis-cli -h host --tls -a ", token, " ping"),
			want:    "ctxcop-redis-auth-cli",
		},
		{
			name:    "redis-cli --pass quoted",
			content: join("redis-cli --pass '", token, "' info"),
			want:    "ctxcop-redis-auth-cli",
		},
		{
			name:    "redis-cli -a bare",
			content: join("redis-cli -a ", token),
			want:    "ctxcop-redis-auth-cli",
		},
		{
			name:    "redis-cli env-var reference is left alone",
			content: "redis-cli -a $REDIS_PASS ping",
			notWant: "ctxcop-redis-auth-cli",
		},
		{
			// Floor guard: a sub-8-char "secret" trips Splice's
			// over-redact backstop against unrelated lines carrying the
			// same short form.
			name:    "redis-cli 7-char value under floor is left alone",
			content: "redis-cli --pass short12 ping",
			notWant: "ctxcop-redis-auth-cli",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fired := firedRules(t, tc.content)
			if tc.want != "" && !fired[tc.want] {
				t.Fatalf("expected %s to fire; fired=%v", tc.want, keys(fired))
			}
			if tc.notWant != "" && fired[tc.notWant] {
				t.Fatalf("expected %s NOT to fire; fired=%v", tc.notWant, keys(fired))
			}
		})
	}
}
