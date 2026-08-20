package redact

import "fmt"

// MaxWalkDepth bounds JSON-tree recursion against pathological MCP payloads.
// On exceedance: scanners under-detect, RedactTree leaves the subtree
// untouched — fail-safe in both directions, harnesses layer fail-open.
const MaxWalkDepth = 64

// redactLeaf redacts a single string node, honoring markers only when the
// tree carries authored content (see FirstHit vs FirstHitToolOutput).
func redactLeaf(s string, honorMarkers bool) (string, []string, error) {
	if honorMarkers {
		return RedactWithMatches(s)
	}
	return RedactToolOutput(s)
}

// FirstHit walks v and returns (true, dotted-path, ruleIDs) on first match.
// Path shape: k1.k2[3].k4 (matches audit-log format). HONORS allow/fixture
// markers — for AUTHORED trees (e.g. an MCP tool's input args).
func FirstHit(v any) (bool, string, []string) {
	return firstHit("", v, 0, true)
}

// FirstHitToolOutput is FirstHit for UNTRUSTED tool-output trees (WebFetch/MCP
// responses): it does NOT honor allow/fixture markers (issue #56).
func FirstHitToolOutput(v any) (bool, string, []string) {
	return firstHit("", v, 0, false)
}

func firstHit(prefix string, v any, depth int, honorMarkers bool) (bool, string, []string) {
	if depth > MaxWalkDepth {
		return false, "", nil
	}
	switch t := v.(type) {
	case string:
		if t == "" {
			return false, "", nil
		}
		_, rules, err := redactLeaf(t, honorMarkers)
		if err == nil && len(rules) > 0 {
			return true, prefix, rules
		}
	case map[string]any:
		for k, vv := range t {
			p := k
			if prefix != "" {
				p = prefix + "." + k
			}
			if hit, field, rules := firstHit(p, vv, depth+1, honorMarkers); hit {
				return true, field, rules
			}
		}
	case []any:
		for i, vv := range t {
			p := fmt.Sprintf("%s[%d]", prefix, i)
			if hit, field, rules := firstHit(p, vv, depth+1, honorMarkers); hit {
				return true, field, rules
			}
		}
	}
	return false, "", nil
}

// AllHits walks the tree and returns dedup'd rule IDs + dotted paths. HONORS
// allow/fixture markers — for AUTHORED trees (e.g. tool-call input args).
func AllHits(v any) (ruleIDs []string, fields []string) {
	return allHits(v, true)
}

// AllHitsToolOutput is AllHits for UNTRUSTED tool-output trees: it does NOT
// honor allow/fixture markers (issue #56).
func AllHitsToolOutput(v any) (ruleIDs []string, fields []string) {
	return allHits(v, false)
}

func allHits(v any, honorMarkers bool) (ruleIDs []string, fields []string) {
	seenRules := map[string]struct{}{}
	seenFields := map[string]struct{}{}
	addRules := func(rs []string) {
		for _, r := range rs {
			if _, ok := seenRules[r]; ok {
				continue
			}
			seenRules[r] = struct{}{}
			ruleIDs = append(ruleIDs, r)
		}
	}
	addField := func(p string) {
		if p == "" {
			p = "(root)"
		}
		if _, ok := seenFields[p]; ok {
			return
		}
		seenFields[p] = struct{}{}
		fields = append(fields, p)
	}
	var walk func(string, any, int)
	walk = func(path string, node any, depth int) {
		if depth > MaxWalkDepth {
			return
		}
		switch t := node.(type) {
		case string:
			_, rules, err := redactLeaf(t, honorMarkers)
			if err == nil && len(rules) > 0 {
				addRules(rules)
				addField(path)
			}
		case map[string]any:
			for k, v := range t {
				p := k
				if path != "" {
					p = path + "." + k
				}
				walk(p, v, depth+1)
			}
		case []any:
			for i, v := range t {
				walk(fmt.Sprintf("%s[%d]", path, i), v, depth+1)
			}
		}
	}
	walk("", v, 0)
	return ruleIDs, fields
}

// RedactTree returns a deep copy of v with every string redacted, plus
// the dedup'd rule IDs that fired. Non-string scalars and unsupported
// types pass through unchanged. HONORS allow/fixture markers — for AUTHORED
// or outbound trees.
func RedactTree(v any) (any, []string) {
	return redactTree(v, true)
}

// RedactTreeToolOutput is RedactTree for UNTRUSTED tool-output trees
// (WebFetch/MCP responses): it does NOT honor allow/fixture markers so a
// planted marker can't suppress redaction of the response (issue #56).
func RedactTreeToolOutput(v any) (any, []string) {
	return redactTree(v, false)
}

func redactTree(v any, honorMarkers bool) (any, []string) {
	var allRules []string
	seen := map[string]struct{}{}
	addRules := func(rs []string) {
		for _, r := range rs {
			if _, ok := seen[r]; ok {
				continue
			}
			seen[r] = struct{}{}
			allRules = append(allRules, r)
		}
	}
	var walk func(any, int) any
	walk = func(node any, depth int) any {
		if depth > MaxWalkDepth {
			return node
		}
		switch t := node.(type) {
		case string:
			out, rules, err := redactLeaf(t, honorMarkers)
			if err != nil {
				return t
			}
			if len(rules) == 0 {
				return t
			}
			addRules(rules)
			return out
		case map[string]any:
			out := make(map[string]any, len(t))
			for k, v := range t {
				out[k] = walk(v, depth+1)
			}
			return out
		case []any:
			out := make([]any, len(t))
			for i, v := range t {
				out[i] = walk(v, depth+1)
			}
			return out
		default:
			return node
		}
	}
	return walk(v, 0), allRules
}
