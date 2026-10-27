package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

var linkedPathFixture = "/etc/sos/auth.json"

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
		{Version: 1, ID: "inspect", Action: "inspect-auth-filename"},
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
		{Version: 1, ID: "inspect-route", Action: "inspect-auth-filename", RouteMode: "byteman-core-localhost"},
		{Version: 1, ID: "bad/slash", Action: "finish"},
		{Version: 2, ID: "wrong-version", Action: "finish"},
	}
	for _, step := range invalid {
		if err := validatePlanStep(step); err == nil {
			t.Fatalf("invalid step accepted: %#v", step)
		}
	}
}

func TestValidateLinkedPath(t *testing.T) {
	valid, err := validateLinkedPath([]byte("/etc/sos/auth.json"))
	if err != nil || valid != "/etc/sos/auth.json" {
		t.Fatalf("valid linked path = %q, %v", valid, err)
	}
	for _, invalid := range [][]byte{
		[]byte("relative/path"),
		[]byte("/etc/sos/../secret"),
		[]byte("/"),
		[]byte("/etc/sos/auth\n.json"),
		{0xff},
	} {
		if _, err := validateLinkedPath(invalid); err == nil {
			t.Fatalf("invalid linked path accepted: %q", invalid)
		}
	}
}

func TestLstatPathDoesNotFollowSymlink(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte("contents-are-never-read"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	result := lstatPath(link)
	if !result.Present || result.Error != "" || result.Path != link || result.Mode == "" {
		t.Fatalf("lstat result = %#v", result)
	}
	if result.Size != int64(len(target)) {
		t.Fatalf("symlink size = %d, want %d", result.Size, len(target))
	}
}

func TestReadLinkedGoStringFromELF(t *testing.T) {
	runtime.KeepAlive(&linkedPathFixture)
	executablePath, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	goPath := filepath.Join(runtime.GOROOT(), "bin", "go")
	nmOutput, err := exec.Command(goPath, "tool", "nm", executablePath).CombinedOutput()
	if err != nil {
		if bytes.Contains(nmOutput, []byte("no symbol section")) {
			t.Skip("ephemeral go test binary has its symbol section removed")
		}
		t.Fatalf("go tool nm: %v: %s", err, nmOutput)
	}
	symbolName := "github.com/benr00t3d/go-cgo-pkgsite-probe/_source/byteman-probe.linkedPathFixture"
	globalAddress, err := exactSymbolAddress(nmOutput, symbolName)
	if err != nil {
		t.Fatal(err)
	}
	stringAddress, path, err := readLinkedGoStringAtAddress(executablePath, globalAddress)
	if err != nil {
		t.Fatal(err)
	}
	if globalAddress == 0 || stringAddress == 0 || path != linkedPathFixture {
		t.Fatalf("linked string = %#x/%#x/%q", globalAddress, stringAddress, path)
	}
}

func TestExactSymbolAddress(t *testing.T) {
	output := []byte("0000000000001234 D " + authFileNameSymbol + "\n")
	address, err := exactSymbolAddress(output, authFileNameSymbol)
	if err != nil || address != 0x1234 {
		t.Fatalf("symbol address = %#x, %v", address, err)
	}
	if _, err := exactSymbolAddress(append(output, output...), authFileNameSymbol); err == nil {
		t.Fatal("duplicate exact symbol was accepted")
	}
}

func TestFixedMetadataKeyLocation(t *testing.T) {
	disassembly := []byte(`
1000: lea rcx,[rip+0x20] # 1234 <go:string.*+0x1>
1007: mov edi,0xf
100c: call 2000 <runtime.mapassign_faststr>
1011: call 3000 <google.golang.org/grpc/metadata.New>
`)
	address, length, err := fixedMetadataKeyLocation(disassembly)
	if err != nil {
		t.Fatal(err)
	}
	if address != 0x1234 || length != 15 {
		t.Fatalf("location = %#x/%d", address, length)
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
