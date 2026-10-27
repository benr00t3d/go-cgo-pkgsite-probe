package main

import (
	"bytes"
	"testing"
)

func TestStringFieldEncoding(t *testing.T) {
	got := appendStringField(nil, 2, "x")
	want := []byte{0x12, 0x01, 'x'}
	if !bytes.Equal(got, want) {
		t.Fatalf("field encoding = %x, want %x", got, want)
	}
}

func TestOwnedDownloadRequestShape(t *testing.T) {
	metadata := []byte{}
	metadata = appendStringField(metadata, 2, "https://proxy.golang.org")
	metadata = appendVarintField(metadata, 3, 1)
	metadata = appendStringField(metadata, 4, moduleName)
	metadata = appendVarintField(metadata, 5, 1)
	metadata = appendStringField(metadata, 6, probeVersion)
	request := []byte{}
	request = appendStringField(request, 1, "https://example.invalid/canary")
	request = appendBytesField(request, 4, metadata)
	request = appendStringField(request, 6, "robert-owned-v027-byteman-probe")
	if len(request) == 0 || request[0] != 0x0a {
		t.Fatalf("unexpected request prefix: %x", request)
	}
	for _, required := range [][]byte{
		[]byte(moduleName),
		[]byte(probeVersion),
		[]byte("robert-owned-v027-byteman-probe"),
	} {
		if !bytes.Contains(request, required) {
			t.Fatalf("request does not contain %q", required)
		}
	}
}
