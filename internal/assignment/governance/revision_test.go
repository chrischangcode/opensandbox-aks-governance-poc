package governance

import "testing"

func TestPolicyRevisionUsesUnescapedUTF8(t *testing.T) {
	revision, err := PolicyRevision(map[string]any{
		"governance": map[string]any{"displayName": "R&D café"},
	})
	if err != nil {
		t.Fatal(err)
	}
	const expected = "sha256:727b8796285e041589a366e4085dd86d28e4ab4d236c947296108cb097ed00ef"
	if revision != expected {
		t.Fatalf("PolicyRevision() = %s, want %s", revision, expected)
	}
}
