package main

import "testing"

func TestBoundedBuffer(t *testing.T) {
	var b boundedBuffer
	input := make([]byte, maxOutput+10)
	if n, err := b.Write(input); n != len(input) || err != nil {
		t.Fatalf("Write = %d, %v", n, err)
	}
	if b.buffer.Len() != maxOutput || !b.truncated {
		t.Fatalf("len=%d truncated=%t", b.buffer.Len(), b.truncated)
	}
}

func TestItoa(t *testing.T) {
	for input, want := range map[int]string{1: "1", 9: "9", 10: "10", 42: "42", 100: "100"} {
		if got := itoa(input); got != want {
			t.Fatalf("itoa(%d) = %q, want %q", input, got, want)
		}
	}
}
