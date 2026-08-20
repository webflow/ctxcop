package shellwrap

import "testing"

func TestQuoteUnquoteRoundTrip(t *testing.T) {
	cases := []string{
		"",
		"ruff",
		"ruff check",
		"pytest -x && npm test",
		"CI=1 pytest",
		"cd backend && pytest",
		"can't stop",
		`has "double" quotes`,
		"has\ttab and\nnewline",
		"trailing'quote'",
		"'already quoted'",
		"$HOME `backtick` \\backslash",
	}
	for _, c := range cases {
		q := Quote(c)
		got, ok := Unquote(q)
		if !ok {
			t.Errorf("Unquote(Quote(%q)=%q) failed to parse", c, q)
			continue
		}
		if got != c {
			t.Errorf("round-trip mismatch: Quote(%q)=%q, Unquote=%q", c, q, got)
		}
	}
}

func TestUnquoteRejectsTrailingGarbage(t *testing.T) {
	// A crafted value that looks like a quoted word but has content
	// appended after the closing quote must not be accepted as a
	// single shell word — this is the anchoring that keeps a
	// repo-planted lookalike from being mistaken for a real wrap.
	if _, ok := Unquote("'safe' ; rm -rf /"); ok {
		t.Error("expected trailing content after closing quote to be rejected")
	}
}

func TestUnquoteRejectsUnterminated(t *testing.T) {
	if _, ok := Unquote("'unterminated"); ok {
		t.Error("expected unterminated quote to be rejected")
	}
}

func TestQuoteEmpty(t *testing.T) {
	if got := Quote(""); got != "''" {
		t.Errorf("Quote(\"\") = %q, want ''", got)
	}
}
