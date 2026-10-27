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
	request = appendStringField(request, 6, "robert-owned-v031-codex-byteman-probe")
	if len(request) == 0 || request[0] != 0x0a {
		t.Fatalf("unexpected request prefix: %x", request)
	}
	for _, required := range [][]byte{
		[]byte(moduleName),
		[]byte(probeVersion),
		[]byte("robert-owned-v031-codex-byteman-probe"),
	} {
		if !bytes.Contains(request, required) {
			t.Fatalf("request does not contain %q", required)
		}
	}
}

func TestInternalRPCAddress(t *testing.T) {
	dial, endpoint, err := internalRPCAddress("10.20.30.40", "9000", "rpc.deps.dev")
	if err != nil {
		t.Fatal(err)
	}
	if dial != "10.20.30.40:9000" || endpoint != "https://rpc.deps.dev:9000" {
		t.Fatalf("internal RPC target = %q, %q", dial, endpoint)
	}
	for _, test := range []struct{ host, port string }{
		{"rpc.default.svc", "9000"},
		{"0.0.0.0", "9000"},
		{"10.20.30.40", "0"},
		{"10.20.30.40", "not-a-port"},
	} {
		if _, _, err := internalRPCAddress(test.host, test.port, "rpc.deps.dev"); err == nil {
			t.Fatalf("internalRPCAddress(%q, %q) unexpectedly succeeded", test.host, test.port)
		}
	}
	if _, _, err := internalRPCAddress("10.20.30.40", "9000", "attacker.example"); err == nil {
		t.Fatal("unapproved TLS server name unexpectedly succeeded")
	}
}

func TestPlanStepValidation(t *testing.T) {
	valid := []planStep{
		{Version: 1, ID: "rpc", Action: "probe-byteman", TLSServerName: "rpc.deps.dev"},
		{Version: 1, ID: "sos-rpc", Action: "probe-byteman", TLSServerName: "sos.rpc.deps.dev"},
		{Version: 1, ID: "done", Action: "finish"},
	}
	for _, step := range valid {
		if err := validatePlanStep(step); err != nil {
			t.Fatalf("valid step rejected: %v", err)
		}
	}
	invalid := []planStep{
		{Version: 1, ID: "shell", Action: "exec", TLSServerName: "rpc.deps.dev"},
		{Version: 1, ID: "external", Action: "probe-byteman", TLSServerName: "example.com"},
		{Version: 1, ID: "nested", Action: "probe-byteman", TLSServerName: "a.b.rpc.deps.dev"},
		{Version: 1, ID: "bad/slash", Action: "finish"},
		{Version: 2, ID: "wrong-version", Action: "finish"},
	}
	for _, step := range invalid {
		if err := validatePlanStep(step); err == nil {
			t.Fatalf("invalid step accepted: %#v", step)
		}
	}
}
