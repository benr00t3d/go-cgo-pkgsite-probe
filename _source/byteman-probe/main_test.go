package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
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

func TestCallbackConfigurationIsExact(t *testing.T) {
	priorGeneric, priorCompiler := genericResultURL, compilerResultURL
	priorSession, priorAgent := sessionNonce, probeUserAgent
	sessionNonce = strings.Repeat("a", 64)
	probeUserAgent = expectedUserAgent
	genericResultURL = "https://callback.example.invalid/v1/result/" + sessionNonce + "/generic"
	compilerResultURL = "https://callback.example.invalid/v1/result/" + sessionNonce + "/compiler"
	t.Cleanup(func() {
		genericResultURL, compilerResultURL = priorGeneric, priorCompiler
		sessionNonce, probeUserAgent = priorSession, priorAgent
	})
	if err := validateCallbackConfiguration(); err != nil {
		t.Fatal(err)
	}
	compilerResultURL = "https://other.example.invalid/v1/result/" + sessionNonce + "/compiler"
	if err := validateCallbackConfiguration(); err == nil {
		t.Fatal("split callback origins were accepted")
	}
}

func TestCapslockIdentityGateIsExact(t *testing.T) {
	capslock := "/capslock/modcache/" + moduleName + "@" + probeVersion
	pid1 := "/talisman-worker-capabilities -http=:8080"
	if classifyLaneWithIdentity(capslock, 0, pid1) != "capslock" ||
		classifyLaneWithIdentity(capslock+"/subdir", 0, pid1) != "capslock" {
		t.Fatal("exact Capslock identity was not accepted")
	}
	for _, test := range []struct {
		cwd  string
		uid  int
		pid1 string
	}{
		{capslock, 1000, pid1},
		{capslock, 0, "/sbin/init"},
		{"/capslock/modcache/other@v1", 0, pid1},
		{"/capslock/modcache/" + moduleName + "@v0.0.59-codex", 0, pid1},
	} {
		if classifyLaneWithIdentity(test.cwd, test.uid, test.pid1) == "capslock" {
			t.Fatalf("wrong identity entered Capslock lane: %#v", test)
		}
	}
}

func TestStaticReportSerializationIsMinimal(t *testing.T) {
	identity := identityResult{
		Lane: "capslock", CWD: "/private/cwd",
	}
	report := newProbeReport(time.Unix(1, 0), identity)
	report.FinishedUTC = time.Unix(2, 0).UTC().Format(time.RFC3339Nano)
	report.Inspection = &inspectionResult{}
	report.Reason = "bounded static evidence completed"
	report.TargetModule = "private-target"
	report.Metadata.Email = "private@example.invalid"
	report.Byteman = []grpcResult{{Method: "private-method"}}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{
		[]byte("private/cwd"),
		[]byte("private-target"), []byte("private@example.invalid"), []byte("private-method"),
	} {
		if bytes.Contains(encoded, forbidden) {
			t.Fatalf("static report exposed forbidden value %q: %s", forbidden, encoded)
		}
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"schema", "module", "version", "started_utc", "finished_utc", "identity",
		"inspection", "reason", "process_memory_read", "auth_file_content_read",
		"mutating_requests_attempted", "non_callback_network_requests_attempted",
	}
	if len(decoded) != len(want) {
		t.Fatalf("static report fields = %v", decoded)
	}
	for _, key := range want {
		if _, ok := decoded[key]; !ok {
			t.Fatalf("static report omitted %q", key)
		}
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
		{Version: 1, ID: "inspect", Action: "inspect-auth-init"},
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
		{Version: 1, ID: "inspect-route", Action: "inspect-auth-init", RouteMode: "byteman-core-localhost"},
		{Version: 1, ID: "bad/slash", Action: "finish"},
		{Version: 2, ID: "wrong-version", Action: "finish"},
	}
	for _, step := range invalid {
		if err := validatePlanStep(step); err == nil {
			t.Fatalf("invalid step accepted: %#v", step)
		}
	}
}

func TestExactAuthInitSymbols(t *testing.T) {
	output := []byte("0000000000001000 T " + authInitSymbolPrefix + "\n" +
		"0000000000001010 t " + authInitSymbolPrefix + ".0\n" +
		"0000000000001020 T unrelated.init\n")
	symbols, err := exactAuthInitSymbols(output)
	if err != nil {
		t.Fatal(err)
	}
	if len(symbols) != 2 || symbols[0].Name != authInitSymbolPrefix || symbols[1].Name != authInitSymbolPrefix+".0" {
		t.Fatalf("auth init symbols = %#v", symbols)
	}
	if isBoundedAuthInitSymbol(authInitSymbolPrefix+".;bad") || isBoundedAuthInitSymbol(authInitSymbolPrefix+".") {
		t.Fatal("invalid auth init symbol was accepted")
	}
}

func TestExactFunctionSymbol(t *testing.T) {
	output := []byte("0000000000001234 T " + authLoadFileEntrySymbol + "\n")
	symbol, err := exactFunctionSymbol(output, authLoadFileEntrySymbol)
	if err != nil || symbol.Name != authLoadFileEntrySymbol || symbol.Address != "0x1234" {
		t.Fatalf("function symbol = %#v, %v", symbol, err)
	}
	if _, err := exactFunctionSymbol(append(output, output...), authLoadFileEntrySymbol); err == nil {
		t.Fatal("duplicated exact function symbol was accepted")
	}
	if _, err := exactFunctionSymbol([]byte("0000000000001234 D "+authLoadFileEntrySymbol+"\n"), authLoadFileEntrySymbol); err == nil {
		t.Fatal("data symbol was accepted as executable function")
	}
}

func TestBoundedFunctionDisassemblyAndCalls(t *testing.T) {
	data := []byte("0001: call 0002 <os.ReadFile>\n0003: call 0004 <encoding/json.Unmarshal>\n0005: ret\n")
	evidence := boundedFunctionDisassembly(staticSymbol{Name: authLoadFileEntrySymbol, Address: "0x1"}, data)
	if evidence.DisassemblySHA256 == "" || evidence.LineCount != 3 || evidence.LinesDropped || len(evidence.CallSymbols) != 2 ||
		evidence.CallSymbols[0] != "os.ReadFile" || evidence.CallSymbols[1] != "encoding/json.Unmarshal" {
		t.Fatalf("function evidence = %#v", evidence)
	}
}

func TestBoundedFunctionDisassemblyTruncates(t *testing.T) {
	lines := make([]string, maximumFunctionDisassemblyLines+2)
	for index := range lines {
		lines[index] = strings.Repeat("x", 300)
	}
	evidence := boundedFunctionDisassembly(
		staticSymbol{Name: authLoadFileEntrySymbol, Address: "0x1"},
		[]byte(strings.Join(lines, "\n")),
	)
	if !evidence.LinesDropped || evidence.LineCount != maximumFunctionDisassemblyLines ||
		len(evidence.Lines) != maximumFunctionDisassemblyLines {
		t.Fatalf("function evidence bounds = %#v", evidence)
	}
	for _, line := range evidence.Lines {
		if len(line) > 256+len("[truncated]") {
			t.Fatalf("retained line length = %d", len(line))
		}
	}
}

func TestAuthSourceNameIsPackageBounded(t *testing.T) {
	got, ok := authSourceName("prefix sos.googlesource.com/sos/auth.LoadFileEntry suffix")
	if !ok || got != authLoadFileEntrySymbol {
		t.Fatalf("auth source name = %q/%t", got, ok)
	}
	for _, test := range []struct {
		line string
		want string
		ok   bool
	}{
		{"sos.googlesource.com/sos/other.Load", "", false},
		{"sos.googlesource.com/sos/auth/etc/sos/auth.json", "", false},
		{authFileNameSymbol + "/var/lib/private.json", authFileNameSymbol, true},
		{authLoadFileEntrySymbol + "/run/secrets/auth", authLoadFileEntrySymbol, true},
	} {
		got, ok := authSourceName(test.line)
		if got != test.want || ok != test.ok {
			t.Fatalf("authSourceName(%q) = %q/%t, want %q/%t", test.line, got, ok, test.want, test.ok)
		}
		for _, forbidden := range []string{"/etc/", "/var/", "/run/"} {
			if strings.Contains(got, forbidden) {
				t.Fatalf("canonical auth token retained path suffix %q", got)
			}
		}
	}
}

func TestBoundedInstructionWindows(t *testing.T) {
	data := []byte("one\ntwo\nref auth.FileName\nfour\nfive\nsix\nref auth.FileName\neight\n")
	windows := boundedInstructionWindows(data, "auth.FileName", 1, 1, 2)
	if len(windows) != 2 || len(windows[0]) != 3 || len(windows[1]) != 3 {
		t.Fatalf("bounded instruction windows = %#v", windows)
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
