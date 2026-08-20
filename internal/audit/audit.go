package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Entry is one detection event. Narrow on purpose — for "did ctxcop see
// something interesting", not for forensics rich enough to re-create the
// secret. Prev + Hash form a tamper-evident chain across appends; see
// docs/verify-reproducibility.md's sibling, ctxcop audit verify.
type Entry struct {
	TS     string   `json:"ts"`
	Tool   string   `json:"tool"`
	Action string   `json:"action"`
	Rules  []string `json:"rules,omitempty"`
	Count  int      `json:"count,omitempty"`
	Field  string   `json:"field,omitempty"`
	Prev   string   `json:"prev"`
	Hash   string   `json:"hash"`
}

// computeHash returns hex(sha256(canonical(entry with Hash zeroed))).
// Go's json.Marshal serializes struct fields in declaration order, so
// canonical form is stable as long as Entry's field order doesn't change.
func (e Entry) computeHash() (string, error) {
	e.Hash = ""
	raw, err := json.Marshal(e)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

var (
	mu       sync.Mutex
	forceOff bool
)

// Disable is a test-only kill switch; production opts out by leaving
// $CTXCOP_AUDIT_LOG unset.
func Disable() {
	mu.Lock()
	defer mu.Unlock()
	forceOff = true
}

// Log writes a chained JSON-line entry iff $CTXCOP_AUDIT_LOG is set. Off
// by default — a security tool shouldn't silently retain detection records
// next to the secrets that triggered them. Best-effort; errors swallowed
// so a logging failure can't block a hook call.
//
// Each entry's Prev is the previous entry's Hash, forming a chain
// detectable by `ctxcop audit verify`. After a legacy (unchained) entry,
// the next chained entry restarts the chain from "".
func Log(e Entry) {
	mu.Lock()
	defer mu.Unlock()
	if forceOff {
		return
	}
	path := os.Getenv("CTXCOP_AUDIT_LOG")
	if path == "" {
		return
	}
	if e.TS == "" {
		e.TS = time.Now().UTC().Format(time.RFC3339)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return
	}
	// Hooks are separate processes; the mutex above only serializes
	// goroutines within one. Hold a cross-process advisory lock across the
	// read-Prev + append so two concurrent Log() calls can't observe the
	// same lastHash and both chain off it. Best-effort: a nil lock (locking
	// unsupported/failed) still falls through and appends — never crash the
	// hook over audit logging.
	lock := acquireLock(path)
	defer lock.release()
	e.Prev = lastHash(path)
	h, err := e.computeHash()
	if err != nil {
		return
	}
	e.Hash = h
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	_ = json.NewEncoder(f).Encode(e)
}

// lastHash returns the Hash of the last entry in the file, or "" if
// the file is missing/empty/the last line is legacy (no Hash field).
// On any read or parse error, returns "" — fail-open from the writer.
func lastHash(path string) string {
	line, ok := lastLine(path)
	if !ok {
		return ""
	}
	var prev Entry
	if err := json.Unmarshal([]byte(line), &prev); err != nil {
		return ""
	}
	return prev.Hash
}

// lastLine returns the last non-empty line of the file without reading the
// whole file — it scans backward from EOF in chunks, so appending N entries
// over a session stays O(N) rather than O(N²). Returns ok=false if the file
// is missing/empty/all-whitespace or unreadable (fail-open from the writer).
func lastLine(path string) (string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer func() { _ = f.Close() }()

	size, err := f.Seek(0, io.SeekEnd)
	if err != nil || size == 0 {
		return "", false
	}

	const chunk = 4096
	var tail []byte
	pos := size
	for pos > 0 {
		n := int64(chunk)
		if pos < n {
			n = pos
		}
		pos -= n
		buf := make([]byte, n)
		if _, err := f.ReadAt(buf, pos); err != nil {
			return "", false
		}
		tail = append(buf, tail...)
		// Drop trailing newlines so the segment after the final '\n' is the
		// real last line, not an empty tail.
		trimmed := bytes.TrimRight(tail, " \t\r\n")
		if idx := bytes.LastIndexByte(trimmed, '\n'); idx >= 0 {
			return string(bytes.TrimSpace(trimmed[idx+1:])), true
		}
		if pos == 0 {
			if line := bytes.TrimSpace(trimmed); len(line) > 0 {
				return string(line), true
			}
		}
	}
	return "", false
}
