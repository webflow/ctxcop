package claudecode

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// realPayloadShape is the exact key set Claude Code 2.1.x sends to the
// Elicitation / ElicitationResult hooks, captured from
// testing/elicit-mcp/'s stdin-tee experiment (see #5 for the original
// drift report and #3 RESULT.md for the methodology). Every test in
// this file uses this shape rather than the legacy snake_case-with-
// tool_name shape — the legacy shape is exactly the schema that
// silently shipped a broken `MCP server ""` notice for v0.2.0.

func TestElicitationPassthroughOnRealPayload(t *testing.T) {
	in := `{"mcp_server_name":"vault","mode":"form","request":{"type":"form","fields":[{"name":"path","type":"string"}]},"hook_event_name":"Elicitation"}`
	var out bytes.Buffer
	if err := Elicitation(strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != "{}" {
		t.Errorf("Elicitation is observation-only; expected passthrough, got %q", got)
	}
}

func TestElicitationBadInputFailsOpen(t *testing.T) {
	var out bytes.Buffer
	if err := Elicitation(strings.NewReader("not-json"), &out); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != "{}" {
		t.Errorf("bad input must fail open, got %q", got)
	}
}

func TestElicitationResultNoticesSecretWithoutModifying(t *testing.T) {
	body := `{"mcp_server_name":"acme","mode":"form","action":"accept","content":{"api_key":"` + akia + `","note":"hello"},"hook_event_name":"ElicitationResult"}`
	var out bytes.Buffer
	if err := ElicitationResult(strings.NewReader(body), &out); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(out.Bytes(), &m); err != nil {
		t.Fatalf("decode: %v (%q)", err, out.String())
	}
	// Observe-only mode: we must NOT emit a hookSpecificOutput.content
	// override (which would silently rewrite the user's submission).
	// A top-level systemMessage is the only thing we want to surface.
	if _, nested := m["hookSpecificOutput"]; nested {
		t.Errorf("observe-only ElicitationResult must not emit hookSpecificOutput (would silently override user's submission); got: %q", out.String())
	}
	msg, _ := m["systemMessage"].(string)
	// The notice has to do three things: anchor on the MCP spec,
	// explain WHY this is a dangerous pattern, and give the user a
	// concrete action. Each one is a separate failure mode in the
	// real-world UX, so each gets its own assertion.
	for _, want := range []string{
		"modelcontextprotocol.io/specification", // spec link present
		"forbids form-mode elicitations",        // explains why it's a violation
		"URL-mode",                              // points at the correct mechanism
		"rotate",                                // gives the actionable next step
		"observation-only",                      // sets correct expectation that we did NOT redact
		"ctxcop-aws-access-key",                 // names which rule fired (audit-traceability)
		"acme",                                  // names the offending MCP server
		"api_key",                               // names the offending field
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("systemMessage missing %q: %q", want, msg)
		}
	}
	// And under no circumstances should the literal credential value
	// appear in the notice we're sending to the model — that would
	// defeat the whole purpose.
	if strings.Contains(msg, akia) {
		t.Errorf("systemMessage leaks the literal secret value: %q", msg)
	}
}

// Regression for #5: prior struct used `json:"server_name"`, so
// ServerName always unmarshaled to "" and the systemMessage rendered
// `MCP server ""` with literal empty quotes. Asserting the absence of
// that artifact protects against re-introducing the bug if someone
// renames the field back.
func TestElicitationResultNoticeNeverContainsEmptyQuotes(t *testing.T) {
	// Same shape as above; the server name is set, so the empty-quote
	// case shouldn't appear regardless of whether the format string
	// uses %q or a conditional label.
	body := `{"mcp_server_name":"acme","mode":"form","action":"accept","content":{"api_key":"` + akia + `"},"hook_event_name":"ElicitationResult"}`
	var out bytes.Buffer
	if err := ElicitationResult(strings.NewReader(body), &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), `""`) {
		t.Errorf(`systemMessage contains literal "" — the broken empty-server-name artifact from #5; got: %q`, out.String())
	}
}

// Defensive coverage: if Claude Code ever omits `mcp_server_name`
// (or the upstream schema drifts again), we must NOT produce a notice
// with empty quotes where the server name should be. The notice
// should fall back to a generic phrase.
func TestElicitationResultHandlesMissingServerName(t *testing.T) {
	body := `{"mode":"form","action":"accept","content":{"api_key":"` + akia + `"},"hook_event_name":"ElicitationResult"}`
	var out bytes.Buffer
	if err := ElicitationResult(strings.NewReader(body), &out); err != nil {
		t.Fatal(err)
	}
	msg := out.String()
	if strings.Contains(msg, `""`) {
		t.Errorf(`empty-server-name case must not render literal "": %q`, msg)
	}
	if !strings.Contains(msg, "the MCP server") {
		t.Errorf("expected generic 'the MCP server' fallback when name missing, got: %q", msg)
	}
}

// URL-mode elicitation is the spec's safe path for credential capture
// (draft 2025-11-25): the credential is captured out-of-band and
// never enters the MCP transport or LLM context. Emitting our
// "consider migrating to URL-mode" notice when the user is ALREADY on
// URL-mode would be backwards and noisy.
func TestElicitationResultPassesThroughURLMode(t *testing.T) {
	body := `{"mcp_server_name":"acme","mode":"url","action":"accept","content":{"redirect":"https://acme.example/oauth"},"hook_event_name":"ElicitationResult"}`
	var out bytes.Buffer
	if err := ElicitationResult(strings.NewReader(body), &out); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != "{}" {
		t.Errorf("URL-mode must passthrough (spec-recommended credential path), got %q", got)
	}
}

// Even if URL-mode somehow surfaces a credential-shape value in
// `content` (it shouldn't, by spec, but defensive coverage), we still
// passthrough — URL mode itself isn't a violation and the warning
// text is wrong for it.
func TestElicitationResultURLModeIgnoresContent(t *testing.T) {
	body := `{"mcp_server_name":"acme","mode":"url","action":"accept","content":{"token":"` + akia + `"},"hook_event_name":"ElicitationResult"}`
	var out bytes.Buffer
	if err := ElicitationResult(strings.NewReader(body), &out); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != "{}" {
		t.Errorf("URL-mode passthrough must hold even with credential-shape content, got %q", got)
	}
}

func TestElicitationResultPassesCleanContent(t *testing.T) {
	body := `{"mcp_server_name":"acme","mode":"form","action":"accept","content":{"name":"alice","age":"30"},"hook_event_name":"ElicitationResult"}`
	var out bytes.Buffer
	if err := ElicitationResult(strings.NewReader(body), &out); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != "{}" {
		t.Errorf("clean content should passthrough, got %q", got)
	}
}

func TestElicitationResultIgnoresNonAcceptActions(t *testing.T) {
	// decline / cancel mean the form is being rejected anyway — no
	// content is going back to the MCP server, no scan needed.
	body := `{"mcp_server_name":"acme","mode":"form","action":"decline","content":{"api_key":"` + akia + `"},"hook_event_name":"ElicitationResult"}`
	var out bytes.Buffer
	if err := ElicitationResult(strings.NewReader(body), &out); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != "{}" {
		t.Errorf("non-accept action should passthrough, got %q", got)
	}
}

func TestElicitationResultBadInputFailsOpen(t *testing.T) {
	var out bytes.Buffer
	if err := ElicitationResult(strings.NewReader("oops"), &out); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != "{}" {
		t.Errorf("bad input must fail open, got %q", got)
	}
}
