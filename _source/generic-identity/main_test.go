package main

import "testing"

func TestValidNonce(t *testing.T) {
	if !validNonce("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef") {
		t.Fatal("valid nonce rejected")
	}
	for _, value := range []string{"", "abc", "g123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"} {
		if validNonce(value) {
			t.Fatalf("invalid nonce accepted: %q", value)
		}
	}
}

func TestExactHTTPS(t *testing.T) {
	want := "/v1/result/session/generic-identity"
	if _, err := exactHTTPS("https://example.test"+want, want); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		"http://example.test" + want,
		"https://example.test/other",
		"https://example.test" + want + "?x=1",
		"https://user@example.test" + want,
	} {
		if _, err := exactHTTPS(raw, want); err == nil {
			t.Fatalf("unsafe URL accepted: %s", raw)
		}
	}
}
