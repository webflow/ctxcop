package redact

import (
	"strings"
	"testing"
)

const walkAKIA = "AKIA" + "LALEMEL33243OLIA"

func TestFirstHitFindsSecret(t *testing.T) {
	tree := map[string]any{
		"outer": map[string]any{
			"inner": []any{"clean", "key=" + walkAKIA},
		},
	}
	hit, field, rules := FirstHit(tree)
	if !hit {
		t.Fatalf("FirstHit should fire")
	}
	if field != "outer.inner[1]" {
		t.Errorf("path = %q, want outer.inner[1]", field)
	}
	if len(rules) == 0 {
		t.Errorf("no rules returned")
	}
}

func TestFirstHitCleanTreeNoHit(t *testing.T) {
	tree := map[string]any{"k": "no secrets here", "n": []any{1.0, true, nil}}
	if hit, _, _ := FirstHit(tree); hit {
		t.Errorf("FirstHit should not fire on clean tree")
	}
}

func TestAllHitsDeduplicatesRules(t *testing.T) {
	tree := map[string]any{
		"a": walkAKIA,
		"b": walkAKIA, // same secret twice
	}
	rules, fields := AllHits(tree)
	if len(rules) != 1 {
		t.Errorf("rules dedup expected 1 unique, got %v", rules)
	}
	if len(fields) != 2 {
		t.Errorf("fields = %v, want both a and b", fields)
	}
}

func TestRedactTreeReplacesStrings(t *testing.T) {
	tree := map[string]any{
		"creds":    "key=" + walkAKIA,
		"count":    3.0,
		"flag":     true,
		"children": []any{walkAKIA, "clean"},
	}
	out, rules := RedactTree(tree)
	if len(rules) == 0 {
		t.Fatalf("no rules fired")
	}
	m := out.(map[string]any)
	if strings.Contains(m["creds"].(string), walkAKIA) {
		t.Errorf("creds string still contains the secret: %v", m["creds"])
	}
	if m["count"] != 3.0 || m["flag"] != true {
		t.Errorf("non-string scalars mutated: %v", m)
	}
	children := m["children"].([]any)
	if strings.Contains(children[0].(string), walkAKIA) {
		t.Errorf("array element still contains secret: %v", children[0])
	}
	if children[1].(string) != "clean" {
		t.Errorf("clean string mutated: %v", children[1])
	}
}

// TestWalkDepthCap is the M3 stack-blowup guard. Build a deeper-than-
// cap structure and confirm FirstHit/AllHits/RedactTree all terminate
// without panicking. The deep leaf credential intentionally goes
// unscanned beyond the cap — under-detection is preferred over crash.
func TestWalkDepthCap(t *testing.T) {
	build := func(depth int) any {
		var v any = walkAKIA
		for i := 0; i < depth; i++ {
			v = map[string]any{"x": v}
		}
		return v
	}
	deep := build(MaxWalkDepth + 50)

	// FirstHit
	if hit, _, _ := FirstHit(deep); hit {
		t.Errorf("FirstHit should under-detect past depth cap, got hit")
	}
	// AllHits
	if rules, _ := AllHits(deep); len(rules) != 0 {
		t.Errorf("AllHits should under-detect past depth cap, got %v", rules)
	}
	// RedactTree
	out, rules := RedactTree(deep)
	if len(rules) != 0 {
		t.Errorf("RedactTree should under-detect past depth cap, got %v", rules)
	}
	if out == nil {
		t.Errorf("RedactTree returned nil for deep input")
	}

	// Shallow enough to scan still works.
	shallow := build(10)
	if hit, _, _ := FirstHit(shallow); !hit {
		t.Errorf("FirstHit should fire at depth 10")
	}
}
