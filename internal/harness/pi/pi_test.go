package pi

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

// ---- BeforeProviderRequest -------------------------------------------------

func TestBeforeProviderRequestRedactsAnthropicPayload(t *testing.T) {
	// Realistic Anthropic Messages-API shape with the credential
	// embedded a few levels deep in the message history (where a
	// prior tool result would have parked it).
	body := `{
        "payload": {
            "model": "claude-haiku-4-5",
            "messages": [
                {"role": "user", "content": [{"type": "text", "text": "hello"}]},
                {"role": "assistant", "content": [{"type": "text", "text": "ok"}]},
                {"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": "t1",
                     "content": "{\"key\":\"` + akia + `\"}"}
                ]}
            ],
            "system": [{"type": "text", "text": "you are an assistant"}]
        }
    }`
	var out bytes.Buffer
	if err := BeforeProviderRequest(strings.NewReader(body), &out); err != nil {
		t.Fatal(err)
	}
	var resp map[string]any
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v (%q)", err, out.String())
	}
	// We MUST return a `payload` key so Pi's runner replaces the body.
	payload, ok := resp["payload"]
	if !ok {
		t.Fatalf("expected `payload` key in response to trigger replacement, got: %q", out.String())
	}
	// And the literal credential MUST be gone from anywhere in the tree.
	// `json.Marshal` unicode-escapes `<` to `<` by default, so
	// we look for the rule-id substring of the placeholder which
	// survives encoding intact.
	serialized, _ := json.Marshal(payload)
	if strings.Contains(string(serialized), akia) {
		t.Errorf("literal credential survived the redact pass: %q", serialized)
	}
	if !strings.Contains(string(serialized), "REDACTED:ctxcop-aws-access-key") {
		t.Errorf("expected redaction placeholder in mutated payload, got: %q", serialized)
	}
}

// #81: the outbound provider payload is egress-side and carries content
// ctxcop does not control, so an inline allow-marker must NOT suppress
// redaction. Before the fix this handler used the marker-honoring
// RedactTree and a planted marker let the literal reach the provider.
//
// Note the assertion shape: on passthrough the handler emits `{}` and Pi
// keeps the ORIGINAL body, so "akia absent from the response" is not
// sufficient — it is exactly what a leak looks like. We require the
// `payload` key (replacement actually triggered) and the placeholder.
func TestBeforeProviderRequestIgnoresAllowMarkers(t *testing.T) {
	for _, marker := range []string{"gitleaks:allow", "ctxcop:allow", "ctxcop:fixture"} {
		t.Run(marker, func(t *testing.T) {
			body := `{
                "payload": {
                    "messages": [
                        {"role": "user", "content": [
                            {"type": "tool_result", "tool_use_id": "t1",
                             "content": "key=` + akia + ` # ` + marker + `"}
                        ]}
                    ]
                }
            }`
			var out bytes.Buffer
			if err := BeforeProviderRequest(strings.NewReader(body), &out); err != nil {
				t.Fatal(err)
			}
			var resp map[string]any
			if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
				t.Fatalf("decode: %v (%q)", err, out.String())
			}
			payload, ok := resp["payload"]
			if !ok {
				t.Fatalf("marker %q suppressed redaction: no `payload` key, so Pi sends the ORIGINAL body with the literal intact (%q)", marker, out.String())
			}
			serialized, _ := json.Marshal(payload)
			if strings.Contains(string(serialized), akia) {
				t.Errorf("marker %q let the literal survive: %q", marker, serialized)
			}
			if !strings.Contains(string(serialized), "REDACTED:ctxcop-aws-access-key") {
				t.Errorf("expected placeholder despite marker %q, got: %q", marker, serialized)
			}
		})
	}
}

func TestBeforeProviderRequestPassesCleanPayload(t *testing.T) {
	body := `{"payload":{"model":"claude-haiku-4-5","messages":[{"role":"user","content":[{"type":"text","text":"hello"}]}]}}`
	var out bytes.Buffer
	if err := BeforeProviderRequest(strings.NewReader(body), &out); err != nil {
		t.Fatal(err)
	}
	// Clean = passthrough = "{}" (no payload key); Pi's runner sees
	// undefined and keeps currentPayload unchanged. Avoids the
	// serialization cost on a clean payload.
	if got := strings.TrimSpace(out.String()); got != "{}" {
		t.Errorf("expected passthrough on clean payload, got %q", got)
	}
}

func TestBeforeProviderRequestFailsOpenOnGarbage(t *testing.T) {
	var out bytes.Buffer
	if err := BeforeProviderRequest(strings.NewReader("not-json"), &out); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != "{}" {
		t.Errorf("bad input must fail open, got %q", got)
	}
}

func TestBeforeProviderRequestNilPayloadPassesThrough(t *testing.T) {
	// Defensive: if Pi ever sends an empty event (it shouldn't),
	// we don't want to crash or block.
	var out bytes.Buffer
	if err := BeforeProviderRequest(strings.NewReader(`{}`), &out); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != "{}" {
		t.Errorf("nil payload must passthrough, got %q", got)
	}
}

// ---- BeforeAgentStart ------------------------------------------------------

func TestBeforeAgentStartAppendsPriming(t *testing.T) {
	body := `{"systemPrompt":"You are an assistant."}`
	var out bytes.Buffer
	if err := BeforeAgentStart(strings.NewReader(body), &out); err != nil {
		t.Fatal(err)
	}
	var resp map[string]any
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v (%q)", err, out.String())
	}
	sp, _ := resp["systemPrompt"].(string)
	if !strings.HasPrefix(sp, "You are an assistant.") {
		t.Errorf("priming must APPEND to the incoming system prompt; got %q", sp)
	}
	for _, want := range []string{
		"ctxcop is active",
		"$ENV_VAR",
		"process.env.X",
		"REDACTED:",
		"MCP tools that take credential-shaped input",
	} {
		if !strings.Contains(sp, want) {
			t.Errorf("priming missing %q: %q", want, sp)
		}
	}
}

func TestBeforeAgentStartFailsOpen(t *testing.T) {
	var out bytes.Buffer
	if err := BeforeAgentStart(strings.NewReader("not-json"), &out); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != "{}" {
		t.Errorf("bad input must fail open, got %q", got)
	}
}

// ---- ToolCall --------------------------------------------------------------

func TestToolCallBlocksMCPCredentialInput(t *testing.T) {
	body := `{"toolName":"mcp__zendesk__create_ticket","toolCallId":"t1","input":{"title":"hi","body":"key is ` + akia + `"}}`
	var out bytes.Buffer
	if err := ToolCall(strings.NewReader(body), &out); err != nil {
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
		"mcp__zendesk__create_ticket",
		"ctxcop-aws-access-key",
		"body",
		".mcp.json",
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

func TestToolCallPassesNonMCPTools(t *testing.T) {
	// Bash with a credential in the command MUST passthrough — by
	// design, bash runs locally and we redact its output downstream
	// at before_provider_request. Blocking here would break the
	// legitimate "use AKIA… from env" patterns.
	body := `{"toolName":"bash","toolCallId":"t1","input":{"command":"AWS_ACCESS_KEY_ID=` + akia + ` aws s3 ls"}}`
	var out bytes.Buffer
	if err := ToolCall(strings.NewReader(body), &out); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != "{}" {
		t.Errorf("bash with credential must passthrough (handled at before_provider_request), got %q", got)
	}
}

func TestToolCallPassesCleanMCP(t *testing.T) {
	body := `{"toolName":"mcp__zendesk__create_ticket","toolCallId":"t1","input":{"title":"hello","body":"nothing sensitive"}}`
	var out bytes.Buffer
	if err := ToolCall(strings.NewReader(body), &out); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != "{}" {
		t.Errorf("clean MCP input must passthrough, got %q", got)
	}
}

func TestToolCallFailsOpen(t *testing.T) {
	var out bytes.Buffer
	if err := ToolCall(strings.NewReader("garbage"), &out); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != "{}" {
		t.Errorf("bad input must fail open, got %q", got)
	}
}

// ---- BridgeSource ----------------------------------------------------------

func TestBridgeSourceLooksRight(t *testing.T) {
	src := BridgeSource()
	for _, want := range []string{
		`from "@earendil-works/pi-coding-agent"`,
		`pi.on("before_provider_request"`,
		`pi.on("before_agent_start"`,
		`pi.on("tool_call"`,
		`pi.on("session_start"`,
		`"ctxcop"`, // CTXCOP_BIN fallback
	} {
		if !strings.Contains(src, want) {
			t.Errorf("embedded bridge missing %q", want)
		}
	}
}
