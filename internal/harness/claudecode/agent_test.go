package claudecode

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestAgentPrimingPrepended(t *testing.T) {
	in := []byte(`{"tool_name":"Agent","tool_input":{"prompt":"do the thing","subagent_type":"general-purpose"}}`)
	var out bytes.Buffer
	if err := PreToolUse("/usr/local/bin/ctxcop", bytes.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	got := decode(t, out.Bytes())
	hso, _ := got["hookSpecificOutput"].(map[string]any)
	ui, _ := hso["updatedInput"].(map[string]any)
	if ui == nil {
		t.Fatalf("expected priming injection, got %v", got)
	}
	newPrompt, _ := ui["prompt"].(string)
	if !strings.HasPrefix(newPrompt, "ctxcop is active in this session") {
		t.Errorf("priming not prepended: %q", newPrompt)
	}
	if !strings.Contains(newPrompt, "do the thing") {
		t.Errorf("original task lost: %q", newPrompt)
	}
	if ui["subagent_type"] != "general-purpose" {
		t.Errorf("non-prompt fields not preserved: %v", ui)
	}
}

func TestAgentPrimingIdempotent(t *testing.T) {
	// If a parent already injected the priming, don't double-prepend.
	already := "ctxcop is active in this session. blah blah\n\n---\n\nactual task here"
	in, _ := json.Marshal(map[string]any{
		"tool_name":  "Agent",
		"tool_input": map[string]any{"prompt": already},
	})
	var out bytes.Buffer
	if err := PreToolUse("/usr/local/bin/ctxcop", bytes.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != "{}" {
		t.Errorf("expected passthrough for already-primed prompt, got %q", got)
	}
}

func TestTaskAliasAlsoPrimed(t *testing.T) {
	// Claude Code dialects vary — Agent is sometimes registered as "Task".
	in := []byte(`{"tool_name":"Task","tool_input":{"prompt":"hello"}}`)
	var out bytes.Buffer
	if err := PreToolUse("/usr/local/bin/ctxcop", bytes.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	got := decode(t, out.Bytes())
	hso, _ := got["hookSpecificOutput"].(map[string]any)
	ui, _ := hso["updatedInput"].(map[string]any)
	if ui == nil {
		t.Fatalf("Task tool should be primed too: %v", got)
	}
	if newPrompt, _ := ui["prompt"].(string); !strings.HasPrefix(newPrompt, "ctxcop is active") {
		t.Errorf("Task priming not applied: %q", newPrompt)
	}
}
