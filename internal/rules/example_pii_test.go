package rules

import (
	"path/filepath"
	"testing"

	"github.com/webflow/ctxcop/internal/testenv"
)

// The shipped example ruleset (examples/rules/pii-dlp.toml) must parse and load
// cleanly via the CTXCOP_RULES overlay, and its rules must actually match. This
// guards against schema drift silently breaking the opt-in PII/DLP pack.
//
// The sample SSN is assembled from fragments so the test source never contains
// a contiguous secret-shaped literal.
func TestExamplePIIDLPRulesetLoadsAndMatches(t *testing.T) {
	Reset()
	testenv.SetHomeDir(t, t.TempDir())
	t.Setenv("CTXCOP_DISABLE_RULES", "")
	path, err := filepath.Abs(filepath.Join("..", "..", "examples", "rules", "pii-dlp.toml"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("CTXCOP_RULES", path)

	list, err := List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	var found bool
	for _, r := range list {
		if r.ID == "pii-ssn" {
			found = true
			if r.Source != SrcEnv {
				t.Errorf("pii-ssn source = %q want %q", r.Source, SrcEnv)
			}
		}
	}
	if !found {
		t.Fatal("example ruleset did not load pii-ssn (parse error or wrong path?)")
	}

	d, err := LoadDetector()
	if err != nil {
		t.Fatalf("LoadDetector: %v", err)
	}
	sample := "ssn=" + "123-45-" + "6789"
	var matched bool
	for _, f := range d.DetectString(sample) {
		if f.RuleID == "pii-ssn" {
			matched = true
		}
	}
	if !matched {
		t.Errorf("pii-ssn did not match assembled sample")
	}
}
