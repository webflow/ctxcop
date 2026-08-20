package pi

import (
	"encoding/json"
	"io"

	"github.com/webflow/ctxcop/internal/audit"
	"github.com/webflow/ctxcop/internal/pause"
	"github.com/webflow/ctxcop/internal/redact"
)

type beforeProviderRequestInput struct {
	Payload any `json:"payload"`
}

type beforeProviderRequestOutput struct {
	Payload any `json:"payload,omitempty"`
}

// BeforeProviderRequest redacts credential-shaped strings in the
// outbound LLM HTTP body. Fail-open on any error.
//
// The payload is egress-side and carries content ctxcop does not control
// (tool results, file excerpts, model text), so it uses the marker-ignoring
// variant: an inline `gitleaks:allow` planted anywhere in the tree must not
// suppress redaction on its way to the provider (#56, #81).
func BeforeProviderRequest(r io.Reader, w io.Writer) error {
	if pause.IsPaused() {
		return passthrough(w)
	}
	raw, err := io.ReadAll(r)
	if err != nil {
		return passthrough(w)
	}
	var in beforeProviderRequestInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return passthrough(w)
	}
	if in.Payload == nil {
		return passthrough(w)
	}
	mutated, rules := redact.RedactTreeToolOutput(in.Payload)
	if len(rules) == 0 {
		// Skip re-serializing a potentially large tree when nothing changed.
		return passthrough(w)
	}
	audit.Log(audit.Entry{
		Tool:   "Pi:before_provider_request",
		Action: "redacted",
		Rules:  rules,
		Count:  len(rules),
	})
	out := beforeProviderRequestOutput{Payload: mutated}
	if err := json.NewEncoder(w).Encode(out); err != nil {
		return passthrough(w)
	}
	return nil
}
