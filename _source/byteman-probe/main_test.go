package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"net/http"
	"os"
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
	decoded, valid := decodeWireMessage(request, 0)
	if !valid {
		t.Fatal("coordinate lookup did not decode")
	}
	limit := uint64(0)
	for _, field := range decoded.fields {
		if field.number == 10 && field.wire == 0 {
			limit = field.varint
		}
	}
	if limit != lookupRecordLimit || limit <= 1 {
		t.Fatalf("coordinate lookup limit = %d", limit)
	}
}

func grpcTestFrame(message []byte) []byte {
	frame := make([]byte, 5, 5+len(message))
	binary.BigEndian.PutUint32(frame[1:], uint32(len(message)))
	return append(frame, message...)
}

func targetLookupRecord(canaryURL string) []byte {
	metadata := appendStringField(nil, 2, targetRegistry)
	metadata = appendVarintField(metadata, 3, 1)
	metadata = appendStringField(metadata, 4, targetModuleName)
	metadata = appendVarintField(metadata, 5, 1)
	metadata = appendStringField(metadata, 6, targetVersion)
	record := appendStringField(nil, 1, canaryURL)
	record = appendBytesField(record, 2, []byte("opaque digest message"))
	record = appendVarintField(record, 3, targetCanaryBytes)
	record = appendStringField(record, 7, "opaque remaining Download field")
	record = appendBytesField(record, 12, metadata)
	record = appendBytesField(record, 17, []byte("opaque service record id"))
	return record
}

func TestLookupDecoderPinsDownloadAndMetadataSchema(t *testing.T) {
	prior := bytemanCanaryURL
	bytemanCanaryURL = "https://example.invalid/owned-b.zip"
	defer func() { bytemanCanaryURL = prior }()
	response := appendBytesField(nil, 1, targetLookupRecord(bytemanCanaryURL))
	analysis, err := analyzeLookupBody(grpcTestFrame(response))
	if err != nil || analysis.MatchPath != "frame[0].1[0]" || analysis.RecordCount != 1 ||
		analysis.MatchCount != 1 || analysis.MatchSHA256 == "" || analysis.RecordsSHA256 == "" {
		t.Fatalf("exact record decode = %#v, err %v", analysis, err)
	}
	empty, err := analyzeLookupBody(grpcTestFrame(nil))
	if err != nil || empty.RecordCount != 0 || empty.MatchCount != 0 {
		t.Fatalf("empty unary Lookup = %#v, err %v", empty, err)
	}
	if _, err := analyzeLookupBody(append(grpcTestFrame(nil), grpcTestFrame(nil)...)); err == nil {
		t.Fatal("multi-frame unary Lookup response was accepted")
	}
}

func TestLookupDecoderRejectsCrossSiblingAggregation(t *testing.T) {
	prior := bytemanCanaryURL
	bytemanCanaryURL = "https://example.invalid/owned-b.zip"
	defer func() { bytemanCanaryURL = prior }()
	urlOnly := appendStringField(nil, 1, bytemanCanaryURL)
	metadata := appendStringField(nil, 2, targetRegistry)
	metadata = appendVarintField(metadata, 3, 1)
	metadata = appendStringField(metadata, 4, targetModuleName)
	metadata = appendVarintField(metadata, 5, 1)
	metadata = appendStringField(metadata, 6, targetVersion)
	metadataOnly := appendBytesField(nil, 12, metadata)
	response := appendBytesField(nil, 1, urlOnly)
	response = appendBytesField(response, 1, metadataOnly)
	analysis, err := analyzeLookupBody(grpcTestFrame(response))
	if err != nil {
		t.Fatal(err)
	}
	if analysis.RecordCount != 2 || analysis.MatchCount != 0 {
		t.Fatalf("strings split across sibling Downloads produced false match: %#v", analysis)
	}
}

func TestLookupDecoderRequiresExactEnums(t *testing.T) {
	prior := bytemanCanaryURL
	bytemanCanaryURL = "https://example.invalid/owned-b.zip"
	defer func() { bytemanCanaryURL = prior }()
	record := targetLookupRecord(bytemanCanaryURL)
	for index, value := range record {
		if value == 0x18 && index+1 < len(record) && record[index+1] == 0x01 {
			record[index+1] = 0x02
			break
		}
	}
	response := appendBytesField(nil, 1, record)
	analysis, err := analyzeLookupBody(grpcTestFrame(response))
	if err != nil || analysis.MatchCount != 0 {
		t.Fatalf("wrong metadata enum matched: %#v, err %v", analysis, err)
	}
}

func TestDownloadResponseDecoderRequiresExactIdentifiedRecord(t *testing.T) {
	prior := bytemanCanaryURL
	bytemanCanaryURL = "https://example.invalid/owned-b.zip"
	defer func() { bytemanCanaryURL = prior }()
	record := targetLookupRecord(bytemanCanaryURL)
	response := appendBytesField(nil, 1, record)
	response = appendVarintField(response, 3, 200)
	analysis, err := analyzeDownloadBody(grpcTestFrame(response))
	if err != nil || !analysis.Identity.Matched || analysis.Identity.DigestSHA256 == "" ||
		analysis.Identity.IDSHA256 == "" || !analysis.StatusSet || analysis.StatusCode != 200 {
		t.Fatalf("DownloadResponse decode = %#v, err %v", analysis, err)
	}
	missingID := appendStringField(nil, 1, bytemanCanaryURL)
	missingID = appendBytesField(missingID, 2, []byte("opaque digest message"))
	missingID = appendVarintField(missingID, 3, targetCanaryBytes)
	metadata := appendStringField(nil, 2, targetRegistry)
	metadata = appendVarintField(metadata, 3, 1)
	metadata = appendStringField(metadata, 4, targetModuleName)
	metadata = appendVarintField(metadata, 5, 1)
	metadata = appendStringField(metadata, 6, targetVersion)
	missingID = appendBytesField(missingID, 12, metadata)
	if _, err := analyzeDownloadBody(grpcTestFrame(appendBytesField(nil, 1, missingID))); err == nil {
		t.Fatal("DownloadResponse without ID field 17 was accepted")
	}
}

func TestExactLookupPairRequiresReturnedDigestAndID(t *testing.T) {
	base := grpcResult{
		HTTPStatus: http.StatusOK, GRPCStatus: "0", LookupMatchCount: 1,
		LookupMatchSHA256: "record", DigestFieldSHA256: "digest", IDFieldSHA256: "id",
	}
	if !exactLookupPair(base, base, "digest", "id") {
		t.Fatal("identical exact Lookup pair was rejected")
	}
	changed := base
	changed.IDFieldSHA256 = "different"
	if exactLookupPair(base, changed, "digest", "id") {
		t.Fatal("Lookup pair with different service IDs was accepted")
	}
}

func TestStreamDecoderUsesOnlyTopLevelFieldTwo(t *testing.T) {
	payload, err := os.ReadFile("testdata/v0.0.1-crosswrite-canary.zip")
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) != targetCanaryBytes {
		t.Fatalf("real canary bytes = %d", len(payload))
	}
	cutoffs := []int{1, 33, 544, 1701, len(payload)}
	body := []byte{}
	start := 0
	for index, end := range cutoffs {
		message := []byte{}
		if index == 0 {
			message = appendStringField(message, 1, "opaque StreamResponse header")
		}
		message = appendBytesField(message, 2, payload[start:end])
		body = append(body, grpcTestFrame(message)...)
		start = end
	}
	_, got, path, err := analyzeStreamBody(body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) || path != "top-level-field-2" {
		t.Fatalf("stream payload mismatch: bytes=%d path=%q", len(got), path)
	}
	for name, message := range map[string][]byte{
		"field-one":  appendBytesField(nil, 1, payload),
		"field-nine": appendBytesField(nil, 9, payload),
		"nested":     appendBytesField(nil, 1, appendBytesField(nil, 2, payload)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, _, err := analyzeStreamBody(grpcTestFrame(message)); err == nil {
				t.Fatal("canary outside top-level StreamResponse field 2 was accepted")
			}
		})
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
	if got := bytemanAuthorityHost("byteman.default.svc.cluster.local", "localhost", false); got != "byteman.default.svc.cluster.local" {
		t.Fatalf("direct authority host = %q", got)
	}
	if got := bytemanAuthorityHost("10.0.0.1", "rpc.deps.dev", true); got != "rpc.deps.dev" {
		t.Fatalf("gateway authority host = %q", got)
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
