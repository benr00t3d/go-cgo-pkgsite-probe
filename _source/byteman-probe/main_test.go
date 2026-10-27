package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestStringFieldEncoding(t *testing.T) {
	got := appendStringField(nil, 2, "x")
	want := []byte{0x12, 0x01, 'x'}
	if !bytes.Equal(got, want) {
		t.Fatalf("field encoding = %x, want %x", got, want)
	}
}

func TestOwnedDownloadRequestShape(t *testing.T) {
	request := buildTargetDownloadRequest("https://example.invalid/canary")
	if len(request) == 0 || request[0] != 0x0a {
		t.Fatalf("unexpected request prefix: %x", request)
	}
	for _, required := range [][]byte{
		[]byte(targetRegistry),
		[]byte(targetModuleName),
		[]byte(targetVersion),
		[]byte(downloadSource),
	} {
		if !bytes.Contains(request, required) {
			t.Fatalf("request does not contain %q", required)
		}
	}
	for _, forbidden := range [][]byte{[]byte(moduleName), []byte(probeVersion)} {
		if bytes.Contains(request, forbidden) {
			t.Fatalf("cross-package request unexpectedly contains executing A coordinate %q", forbidden)
		}
	}
}

func TestCoordinateLookupRequestShape(t *testing.T) {
	request := buildCoordinateLookupRequest()
	for _, required := range [][]byte{
		[]byte(targetRegistry),
		[]byte(targetModuleName),
		[]byte(targetVersion),
	} {
		if !bytes.Contains(request, required) {
			t.Fatalf("coordinate lookup does not contain %q", required)
		}
	}
	for _, forbidden := range [][]byte{[]byte(moduleName), []byte(probeVersion)} {
		if bytes.Contains(request, forbidden) {
			t.Fatalf("coordinate lookup unexpectedly contains executing A coordinate %q", forbidden)
		}
	}
}

func TestTargetCanaryDigestShape(t *testing.T) {
	if len(targetCanarySHA256) != 64 {
		t.Fatalf("target canary SHA-256 length = %d", len(targetCanarySHA256))
	}
	for _, character := range targetCanarySHA256 {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			t.Fatalf("target canary SHA-256 is not lowercase hexadecimal: %q", targetCanarySHA256)
		}
	}
}

func TestDirectBytemanRoute(t *testing.T) {
	host, port, tlsName, injected, err := bytemanRoute("byteman-core-localhost")
	if err != nil || host != "byteman-core.default.svc.cluster.local" || port != 9000 || tlsName != "localhost" || injected {
		t.Fatalf("direct route = %q, %d, %q, %t, %v", host, port, tlsName, injected, err)
	}
	host, port, tlsName, injected, err = bytemanRoute("byteman-oregon-gateway")
	if err != nil || host != "" || port != 0 || tlsName != "byteman.oregon.int.deps.dev" || !injected {
		t.Fatalf("gateway route = %q, %d, %q, %t, %v", host, port, tlsName, injected, err)
	}
	if _, _, _, _, err := bytemanRoute("arbitrary"); err == nil {
		t.Fatal("arbitrary direct route unexpectedly succeeded")
	}
}

func TestBytemanAuthorityIsSeparateFromLegacyTLSName(t *testing.T) {
	if got := bytemanAuthorityHost("byteman.default.svc.cluster.local", "localhost", false); got != "byteman.default.svc.cluster.local" {
		t.Fatalf("direct authority = %q", got)
	}
	if got := bytemanAuthorityHost("10.0.0.1", "byteman.oregon.int.deps.dev", true); got != "byteman.oregon.int.deps.dev" {
		t.Fatalf("gateway authority = %q", got)
	}
}

func legacyTLSState(t *testing.T, commonName string) (tls.ConnectionState, *x509.CertPool) {
	t.Helper()
	now := time.Now()
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootPublic, rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leafPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, root, leafPublic, rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	return tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf, root}}, roots
}

func TestVerifyLegacyLocalhost(t *testing.T) {
	state, roots := legacyTLSState(t, "localhost")
	if err := verifyLegacyLocalhost(state, roots); err != nil {
		t.Fatalf("valid legacy localhost certificate rejected: %v", err)
	}
	wrongState, wrongRoots := legacyTLSState(t, "not-localhost")
	if err := verifyLegacyLocalhost(wrongState, wrongRoots); err == nil {
		t.Fatal("wrong legacy common name accepted")
	}
	if err := verifyLegacyLocalhost(tls.ConnectionState{}, roots); err == nil {
		t.Fatal("missing peer certificate accepted")
	}
}

func TestPlanStepValidation(t *testing.T) {
	valid := []planStep{
		{Version: 1, ID: "inspect", Action: "inspect-session-dataflow"},
		{Version: 1, ID: "core", Action: "probe-byteman", RouteMode: "byteman-core-localhost"},
		{Version: 1, ID: "oregon", Action: "probe-byteman", RouteMode: "byteman-oregon-gateway"},
		{Version: 1, ID: "done", Action: "finish"},
	}
	for _, step := range valid {
		if err := validatePlanStep(step); err != nil {
			t.Fatalf("valid step rejected: %v", err)
		}
	}
	invalid := []planStep{
		{Version: 1, ID: "shell", Action: "exec", RouteMode: "byteman-core-localhost"},
		{Version: 1, ID: "missing-mode", Action: "probe-byteman"},
		{Version: 1, ID: "arbitrary", Action: "probe-byteman", RouteMode: "external"},
		{Version: 1, ID: "inspect-route", Action: "inspect-session-dataflow", RouteMode: "byteman-core-localhost"},
		{Version: 1, ID: "bad/slash", Action: "finish"},
		{Version: 2, ID: "wrong-version", Action: "finish"},
	}
	for _, step := range invalid {
		if err := validatePlanStep(step); err == nil {
			t.Fatalf("invalid step accepted: %#v", step)
		}
	}
}

func TestInstructionWindow(t *testing.T) {
	got := instructionWindow([]byte("one\ntwo\ncall metadata.New\nfour\nfive\n"), "metadata.New", 1, 1)
	want := []string{"two", "call metadata.New", "four"}
	if len(got) != len(want) {
		t.Fatalf("window = %#v", got)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("window = %#v", got)
		}
	}
}
