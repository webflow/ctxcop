package rules

import (
	"strings"
	"testing"

	"github.com/webflow/ctxcop/internal/testenv"
)

// firedRules runs the detector over content and returns the set of rule IDs
// that produced a finding. It goes through the real detector so entropy/filter
// CEL predicates are exercised exactly as in production.
func firedRules(t *testing.T, content string) map[string]bool {
	t.Helper()
	Reset()
	t.Setenv("CTXCOP_RULES", "")
	t.Setenv("CTXCOP_DISABLE_RULES", "")
	testenv.SetHomeDir(t, t.TempDir())
	t.Chdir(t.TempDir())
	d, err := LoadDetector()
	if err != nil {
		t.Fatalf("LoadDetector: %v", err)
	}
	out := map[string]bool{}
	for _, f := range d.DetectString(content) {
		out[f.RuleID] = true
	}
	return out
}

// Split-literal helper: assembles a sample from fragments so no contiguous
// credential-shaped literal sits in the source file.
func join(parts ...string) string { return strings.Join(parts, "") }

func TestNewCredentialRulesMatchAndAreGated(t *testing.T) {
	// AWS secret access key value (canonical AWS-docs example), split.
	awsSecret := join("wJalrXUtnFEMI", "/K7MDENG/", "bPxRfiCYEXAMPLEKEY")

	cases := []struct {
		name    string
		content string
		want    string // rule ID that must fire
		notWant string // optional: rule ID that must NOT fire
	}{
		{
			name:    "aws secret with keyword",
			content: join("AWS_SECRET_ACCESS_KEY=", awsSecret),
			want:    "ctxcop-aws-secret-access-key",
		},
		{
			name:    "bare 40-char base64 without keyword is NOT an aws secret",
			content: join("cache_id=", awsSecret, " next"),
			notWant: "ctxcop-aws-secret-access-key",
		},
		{
			// Regression: the label alternation was snake_case-only, so the
			// spelling most common in JS/TS config objects slipped through.
			name:    "aws secret with camelCase label",
			content: join("awsSecretAccessKey: \"", awsSecret, "\""),
			want:    "ctxcop-aws-secret-access-key",
		},
		{
			name:    "aws secret with kebab-case label",
			content: join("aws-secret-access-key=", awsSecret),
			want:    "ctxcop-aws-secret-access-key",
		},
		{
			name:    "aws secret with camelCase label and no aws prefix",
			content: join("secretAccessKey=", awsSecret),
			want:    "ctxcop-aws-secret-access-key",
		},
		{
			name:    "aws secret with camelCase short label",
			content: join("awsSecretKey=", awsSecret),
			want:    "ctxcop-aws-secret-access-key",
		},
		{
			name:    "postgres dsn with password",
			content: join("postgres://", "dbadmin", ":", "examplepass123", "@db.internal:5432/prod"),
			want:    "ctxcop-db-connection-uri",
		},
		{
			name:    "postgres dsn WITHOUT credentials is not matched",
			content: join("postgres://", "localhost:5432/mydb"),
			notWant: "ctxcop-db-connection-uri",
		},
		{
			// Regression: redis/amqp authenticate with a password and no
			// username, which the `+` username quantifier could not match.
			name:    "redis dsn with empty username",
			content: join("redis://", ":", "examplepass123", "@cache.internal:6379/0"),
			want:    "ctxcop-db-connection-uri",
		},
		{
			name:    "amqp dsn with empty username",
			content: join("amqp://", ":", "examplepass123", "@mq.internal:5672/vhost"),
			want:    "ctxcop-db-connection-uri",
		},
		{
			// Guard on the looser username quantifier: a host:port with no
			// `@` authority must still not match.
			name:    "redis dsn without credentials is not matched",
			content: join("redis://", "cache.internal:6379/0"),
			notWant: "ctxcop-db-connection-uri",
		},
		{
			name:    "jdbc dsn without credentials is not matched",
			content: join("jdbc:mysql://", "db.internal:3306/prod"),
			notWant: "ctxcop-db-connection-uri",
		},
		{
			name:    "generic url userinfo credential",
			content: join("https://", "svc", ":", "s3cr3t", "wJalrXUtnFEMI7K7MDENGbPxRfiCYEXAMPLEKEY", "@evil.example.com/data"),
			want:    "ctxcop-url-userinfo-credential",
		},
		{
			name:    "url with user but no password is not matched",
			content: join("ssh://", "git", "@github.com/org/repo.git"),
			notWant: "ctxcop-url-userinfo-credential",
		},
		{
			name:    "url userinfo placeholder password is filtered",
			content: join("https://", "user", ":", "password", "@example.com/"),
			notWant: "ctxcop-url-userinfo-credential",
		},
		{
			name:    "sendgrid api key",
			content: join("X-Api-Key: ", "SG.", "aB1cD2eF3gH4iJ5kL6mN7o", ".", "pQ7rS8tU9vW0xY1zA2bC3dE4fG5hI6jK7lM8nO9pQ0r"),
			want:    "ctxcop-sendgrid-api-key",
		},
		{
			name:    "http basic auth header",
			content: join("Authorization: ", "Basic ", "YWRtaW46RkFLRS1FWEFNUExFLVNFQ1JFVA=="),
			want:    "ctxcop-http-basic-auth",
		},
		{
			name:    "bare word basic in prose is not basic auth",
			content: "This plan offers basic authentication and standard support tiers.",
			notWant: "ctxcop-http-basic-auth",
		},

		// --- sourcegraph-access-token override (#78) ---
		//
		// Upstream accepted a bare 40-hex string, which is a Git SHA. Keyword
		// gating is payload-wide, so one mention of the vendor name redacted
		// every commit hash in the payload — and the placeholder itself embeds
		// the rule ID, so a single hit poisoned everything after it.
		{
			name:    "prefixed sourcegraph token still fires",
			content: join("SRC_ACCESS_TOKEN=", "sgp_", "0123456789abcdef0123456789abcdef01234567"),
			want:    "sourcegraph-access-token",
		},
		{
			name:    "prefixed sourcegraph token with instance-id segment still fires",
			content: join("token: ", "sgp_", "0123456789abcdef", "_", "0123456789abcdef0123456789abcdef01234567"),
			want:    "sourcegraph-access-token",
		},
		{
			name:    "bare 40-hex git sha is not a sourcegraph token",
			content: "commit 2c71448f94ebcba5afd7edbe217681fac61fb554",
			notWant: "sourcegraph-access-token",
		},
		{
			// The actual #78 regression: vendor name anywhere in the payload
			// used to open the gate for every bare 40-hex in it.
			name:    "git sha is not redacted just because the payload mentions the vendor",
			content: "we evaluated " + join("source", "graph") + " internally\ncommit 2c71448f94ebcba5afd7edbe217681fac61fb554",
			notWant: "sourcegraph-access-token",
		},
		{
			// Self-amplification: the placeholder embeds the rule ID, which
			// re-satisfied the keyword gate for the rest of the payload.
			name:    "a prior placeholder does not poison later git shas",
			content: "<REDACTED:" + join("source", "graph") + "-access-token:aaaa>\ncommit 2c71448f94ebcba5afd7edbe217681fac61fb554",
			notWant: "sourcegraph-access-token",
		},
		{
			name:    "sha-pinned action ref is not a sourcegraph token",
			content: "  - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1  # v7.0.1",
			notWant: "sourcegraph-access-token",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fired := firedRules(t, tc.content)
			if tc.want != "" && !fired[tc.want] {
				t.Errorf("expected rule %q to fire; fired=%v", tc.want, keys(fired))
			}
			if tc.notWant != "" && fired[tc.notWant] {
				t.Errorf("rule %q must NOT fire on this sample; fired=%v", tc.notWant, keys(fired))
			}
		})
	}
}

func keys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
