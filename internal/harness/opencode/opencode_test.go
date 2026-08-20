package opencode

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/webflow/ctxcop/internal/audit"
)

func init() { audit.Disable() }

// Canonical AWS test fixture. Split so this source file itself is not
// a contiguous credential — ctxcop's own Write hook would otherwise
// block edits to this test.
const akia = "AKIA" + "LALEMEL33243OLIA"

// ---- ToolExecuteBefore -----------------------------------------------------

func TestToolExecuteBeforeBlocksMCPCredentialInput(t *testing.T) {
	body := `{"tool":"zendesk_create_ticket","sessionID":"s1","callID":"c1","args":{"title":"hi","body":"key is ` + akia + `"}}`
	var out bytes.Buffer
	if err := ToolExecuteBefore(strings.NewReader(body), &out); err != nil {
		t.Fatal(err)
	}
	var resp map[string]any
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v (%q)", err, out.String())
	}
	block, _ := resp["block"].(bool)
	if !block {
		t.Fatalf("expected block:true on credential-bearing MCP input, got %q", out.String())
	}
	reason, _ := resp["reason"].(string)
	for _, want := range []string{
		"zendesk_create_ticket",
		"ctxcop-aws-access-key",
		"body",
		"Retry with the credential removed",
	} {
		if !strings.Contains(reason, want) {
			t.Errorf("block reason missing %q: %q", want, reason)
		}
	}
	if strings.Contains(reason, akia) {
		t.Errorf("block reason leaks the literal secret: %q", reason)
	}
}

func TestToolExecuteBeforeBlocksWebfetchCredentialURL(t *testing.T) {
	body := `{"tool":"webfetch","sessionID":"s1","callID":"c1","args":{"url":"https://api.example.com/?token=` + akia + `"}}`
	var out bytes.Buffer
	if err := ToolExecuteBefore(strings.NewReader(body), &out); err != nil {
		t.Fatal(err)
	}
	var resp map[string]any
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v (%q)", err, out.String())
	}
	if block, _ := resp["block"].(bool); !block {
		t.Fatalf("expected block:true on webfetch with credential in url, got %q", out.String())
	}
}

func TestToolExecuteBeforeBlocksWebsearchCredentialQuery(t *testing.T) {
	// websearch (added to OpenCode's built-in tool registry after ctxcop's
	// 1.15.13 pin) makes an outbound HTTP call with the query, same
	// exfil shape as webfetch — must be gated, not left unclassified.
	body := `{"tool":"websearch","sessionID":"s1","callID":"c1","args":{"query":"debug token=` + akia + `"}}`
	var out bytes.Buffer
	if err := ToolExecuteBefore(strings.NewReader(body), &out); err != nil {
		t.Fatal(err)
	}
	var resp map[string]any
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v (%q)", err, out.String())
	}
	if block, _ := resp["block"].(bool); !block {
		t.Fatalf("expected block:true on websearch with credential in query, got %q", out.String())
	}
}

func TestToolExecuteBeforePassesApplyPatchWithCredential(t *testing.T) {
	// apply_patch is a local edit path, not an MCP tool — despite the
	// underscore in its name it must NOT be misclassified as exfil-class
	// (which would false-positive block legitimate patches).
	body := `{"tool":"apply_patch","sessionID":"s1","callID":"c1","args":{"patch":"+AWS_ACCESS_KEY_ID=` + akia + `"}}`
	var out bytes.Buffer
	if err := ToolExecuteBefore(strings.NewReader(body), &out); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != "{}" {
		t.Errorf("apply_patch must passthrough (handled at after), got %q", got)
	}
}

func TestToolExecuteBeforePassesBashWithCredential(t *testing.T) {
	// Bash with a credential in the command MUST passthrough — by
	// design, bash runs locally and we redact its output downstream
	// at tool.execute.after. Blocking here would break legitimate
	// "use AKIA… from env" patterns.
	body := `{"tool":"bash","sessionID":"s1","callID":"c1","args":{"command":"AWS_ACCESS_KEY_ID=` + akia + ` aws s3 ls"}}`
	var out bytes.Buffer
	if err := ToolExecuteBefore(strings.NewReader(body), &out); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != "{}" {
		t.Errorf("bash with credential must passthrough (handled at after), got %q", got)
	}
}

func TestToolExecuteBeforePassesLocalToolsAlways(t *testing.T) {
	for _, tool := range []string{"bash", "read", "write", "edit", "grep", "glob", "ls"} {
		body := `{"tool":"` + tool + `","sessionID":"s1","callID":"c1","args":{"x":"` + akia + `"}}`
		var out bytes.Buffer
		if err := ToolExecuteBefore(strings.NewReader(body), &out); err != nil {
			t.Fatalf("%s: %v", tool, err)
		}
		if got := strings.TrimSpace(out.String()); got != "{}" {
			t.Errorf("local tool %q must passthrough at before, got %q", tool, got)
		}
	}
}

func TestToolExecuteBeforePassesCleanMCP(t *testing.T) {
	body := `{"tool":"zendesk_create_ticket","sessionID":"s1","callID":"c1","args":{"title":"hello","body":"nothing sensitive"}}`
	var out bytes.Buffer
	if err := ToolExecuteBefore(strings.NewReader(body), &out); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != "{}" {
		t.Errorf("clean MCP input must passthrough, got %q", got)
	}
}

func TestToolExecuteBeforeFailsOpen(t *testing.T) {
	var out bytes.Buffer
	if err := ToolExecuteBefore(strings.NewReader("garbage"), &out); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != "{}" {
		t.Errorf("bad input must fail open, got %q", got)
	}
}

// ---- ToolExecuteAfter ------------------------------------------------------

func TestToolExecuteAfterRedactsBashOutput(t *testing.T) {
	body := `{"tool":"bash","sessionID":"s1","callID":"c1","args":{"command":"env"},"output":"AWS_ACCESS_KEY_ID=` + akia + `\nfoo=bar"}`
	var out bytes.Buffer
	if err := ToolExecuteAfter(strings.NewReader(body), &out); err != nil {
		t.Fatal(err)
	}
	var resp map[string]any
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v (%q)", err, out.String())
	}
	got, _ := resp["output"].(string)
	if got == "" {
		t.Fatalf("expected `output` key with redacted text, got %q", out.String())
	}
	if strings.Contains(got, akia) {
		t.Errorf("literal credential survived redact: %q", got)
	}
	if !strings.Contains(got, "REDACTED:ctxcop-aws-access-key") {
		t.Errorf("expected placeholder in mutated output, got: %q", got)
	}
}

func TestToolExecuteAfterRedactsReadOutput(t *testing.T) {
	body := `{"tool":"read","sessionID":"s1","callID":"c1","args":{"filePath":"/tmp/.env"},"output":"# secrets\nKEY=` + akia + `\n"}`
	var out bytes.Buffer
	if err := ToolExecuteAfter(strings.NewReader(body), &out); err != nil {
		t.Fatal(err)
	}
	var resp map[string]any
	_ = json.Unmarshal(out.Bytes(), &resp)
	got, _ := resp["output"].(string)
	if strings.Contains(got, akia) {
		t.Errorf("literal credential survived redact on read: %q", got)
	}
}

func TestToolExecuteAfterPassesCleanOutput(t *testing.T) {
	body := `{"tool":"bash","sessionID":"s1","callID":"c1","args":{"command":"ls"},"output":"foo\nbar\n"}`
	var out bytes.Buffer
	if err := ToolExecuteAfter(strings.NewReader(body), &out); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != "{}" {
		t.Errorf("clean output must passthrough, got %q", got)
	}
}

func TestToolExecuteAfterFailsOpen(t *testing.T) {
	var out bytes.Buffer
	if err := ToolExecuteAfter(strings.NewReader("not-json"), &out); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != "{}" {
		t.Errorf("bad input must fail open, got %q", got)
	}
}

func TestToolExecuteAfterEmptyOutputPassthrough(t *testing.T) {
	body := `{"tool":"bash","sessionID":"s1","callID":"c1","output":""}`
	var out bytes.Buffer
	if err := ToolExecuteAfter(strings.NewReader(body), &out); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != "{}" {
		t.Errorf("empty output must passthrough, got %q", got)
	}
}

// ---- BridgeSource ----------------------------------------------------------

func TestBridgeSourceLooksRight(t *testing.T) {
	src := BridgeSource()
	for _, want := range []string{
		`from "@opencode-ai/plugin"`,
		`"tool.execute.before"`,
		`"tool.execute.after"`,
		`id: "ctxcop"`,
		`"ctxcop"`, // CTXCOP_BIN fallback
	} {
		if !strings.Contains(src, want) {
			t.Errorf("embedded bridge missing %q", want)
		}
	}
}

// ---- isExfilClass ----------------------------------------------------------

func TestIsExfilClass(t *testing.T) {
	cases := []struct {
		tool string
		want bool
	}{
		{"bash", false},
		{"read", false},
		{"write", false},
		{"edit", false},
		{"grep", false},
		{"glob", false},
		{"ls", false},
		{"webfetch", true},
		{"WebFetch", true}, // case-insensitive
		{"zendesk_create_ticket", true},
		{"github_create_issue", true},
		{"todowrite", false},
		{"task", false},
	}
	for _, c := range cases {
		if got := isExfilClass(c.tool); got != c.want {
			t.Errorf("isExfilClass(%q) = %v, want %v", c.tool, got, c.want)
		}
	}
}
