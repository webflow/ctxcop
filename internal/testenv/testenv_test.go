package testenv

import (
	"encoding/json"
	"os"
	"testing"
)

func TestSetHomeDirSetsBothVars(t *testing.T) {
	SetHomeDir(t, "/tmp/fake-home")
	if got := os.Getenv("HOME"); got != "/tmp/fake-home" {
		t.Errorf("HOME = %q, want /tmp/fake-home", got)
	}
	if got := os.Getenv("USERPROFILE"); got != "/tmp/fake-home" {
		t.Errorf("USERPROFILE = %q, want /tmp/fake-home", got)
	}
}

func TestSetTempDirSetsAllThreeVars(t *testing.T) {
	SetTempDir(t, "/tmp/fake-temp")
	for _, name := range []string{"TMPDIR", "TMP", "TEMP"} {
		if got := os.Getenv(name); got != "/tmp/fake-temp" {
			t.Errorf("%s = %q, want /tmp/fake-temp", name, got)
		}
	}
}

func TestJSONStringEscapesBackslashes(t *testing.T) {
	// A Windows-shaped path is the motivating case: backslashes must
	// come back escaped, and the value must round-trip through the
	// standard library's own JSON decoder unchanged.
	in := `C:\Users\runner\AppData\Local\Temp\case1\creds.env`
	got := JSONString(in)
	want := `"C:\\Users\\runner\\AppData\\Local\\Temp\\case1\\creds.env"`
	if got != want {
		t.Errorf("JSONString(%q) = %s, want %s", in, got, want)
	}

	var decoded string
	if err := json.Unmarshal([]byte(got), &decoded); err != nil {
		t.Fatalf("round-trip decode failed: %v", err)
	}
	if decoded != in {
		t.Errorf("round-trip mismatch: got %q, want %q", decoded, in)
	}
}

func TestJSONStringEmpty(t *testing.T) {
	if got := JSONString(""); got != `""` {
		t.Errorf("JSONString(\"\") = %s, want \"\"", got)
	}
}
