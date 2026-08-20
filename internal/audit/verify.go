package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
)

// VerifyResult summarizes an audit-log verification pass.
type VerifyResult struct {
	File         string
	TotalEntries int
	Verified     int
	Legacy       int
	Broken       []BrokenEntry
}

// BrokenEntry locates and labels a single integrity failure.
type BrokenEntry struct {
	Line   int
	Kind   string // "parse" | "hash" | "chain"
	Detail string
}

// Ok reports whether the chain (and every entry's own hash) verified
// cleanly. Legacy entries don't fail Ok — they're surfaced separately.
func (r VerifyResult) Ok() bool { return len(r.Broken) == 0 }

// Verify walks the audit log, recomputes each entry's hash, and checks
// each Prev points at the prior entry's Hash. Legacy entries (no Hash —
// from pre-chain ctxcop versions) are counted and treated as a chain
// reset for the next chained entry.
func Verify(path string) (VerifyResult, error) {
	res := VerifyResult{File: path}
	f, err := os.Open(path)
	if err != nil {
		return res, err
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	lineNo := 0
	prevHash := ""
	for scanner.Scan() {
		lineNo++
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		res.TotalEntries++

		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			res.Broken = append(res.Broken, BrokenEntry{
				Line:   lineNo,
				Kind:   "parse",
				Detail: fmt.Sprintf("invalid JSON: %v", err),
			})
			prevHash = ""
			continue
		}

		if e.Hash == "" {
			res.Legacy++
			prevHash = ""
			continue
		}

		expected, herr := e.computeHash()
		if herr != nil {
			res.Broken = append(res.Broken, BrokenEntry{
				Line:   lineNo,
				Kind:   "hash",
				Detail: fmt.Sprintf("recompute failed: %v", herr),
			})
			prevHash = e.Hash
			continue
		}
		if expected != e.Hash {
			res.Broken = append(res.Broken, BrokenEntry{
				Line:   lineNo,
				Kind:   "hash",
				Detail: fmt.Sprintf("entry tampered: stored %s ≠ recomputed %s", shortHash(e.Hash), shortHash(expected)),
			})
		} else if e.Prev != prevHash {
			res.Broken = append(res.Broken, BrokenEntry{
				Line:   lineNo,
				Kind:   "chain",
				Detail: fmt.Sprintf("chain break: prev=%s, expected %s", shortHash(e.Prev), shortHash(prevHash)),
			})
		} else {
			res.Verified++
		}
		prevHash = e.Hash
	}
	if err := scanner.Err(); err != nil {
		return res, err
	}
	return res, nil
}

func shortHash(h string) string {
	if h == "" {
		return `""`
	}
	if len(h) > 12 {
		return h[:12] + "…"
	}
	return h
}
