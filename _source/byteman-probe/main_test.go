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
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
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

func setValidRuntimeConfigurationForTest(t *testing.T) {
	t.Helper()
	priorGeneric := genericResultURL
	priorCompiler := compilerResultURL
	priorPlan := planURL
	priorCanary := bytemanCanaryURL
	priorSession := sessionNonce
	priorAgent := probeUserAgent
	t.Cleanup(func() {
		genericResultURL = priorGeneric
		compilerResultURL = priorCompiler
		planURL = priorPlan
		bytemanCanaryURL = priorCanary
		sessionNonce = priorSession
		probeUserAgent = priorAgent
	})
	sessionNonce = strings.Repeat("a", 64)
	probeUserAgent = expectedUserAgent
	origin := "https://probe.example.invalid"
	genericResultURL = origin + "/v1/result/" + sessionNonce + "/generic"
	compilerResultURL = origin + "/v1/result/" + sessionNonce + "/compiler"
	planURL = origin + "/v1/plan/" + sessionNonce
	bytemanCanaryURL = origin + "/v1/goproxy/" + sessionNonce +
		"/github.com/benr00t3d/go-byteman-crosswrite-canary/@v/v0.0.1.zip"
}

func TestRuntimeConfigurationPinsSessionOriginAndTargetB(t *testing.T) {
	setValidRuntimeConfigurationForTest(t)
	if err := validateRuntimeConfiguration(); err != nil {
		t.Fatalf("valid configuration rejected: %v", err)
	}
	validCanary := bytemanCanaryURL
	validCompiler := compilerResultURL
	validPlan := planURL
	validSession := sessionNonce
	validAgent := probeUserAgent
	for name, mutate := range map[string]func(){
		"target-a": func() {
			bytemanCanaryURL = strings.Replace(validCanary, targetModuleName, moduleName, 1)
		},
		"foreign-origin": func() {
			compilerResultURL = strings.Replace(validCompiler, "probe.example.invalid", "other.example.invalid", 1)
		},
		"query": func() { bytemanCanaryURL = validCanary + "?substitute=1" },
		"wrong-session-path": func() {
			planURL = strings.Replace(validPlan, validSession, strings.Repeat("b", 64), 1)
		},
		"invalid-session": func() { sessionNonce = strings.Repeat("A", 64) },
		"wrong-agent":     func() { probeUserAgent = "other" },
	} {
		t.Run(name, func(t *testing.T) {
			bytemanCanaryURL = validCanary
			compilerResultURL = validCompiler
			planURL = validPlan
			sessionNonce = validSession
			probeUserAgent = validAgent
			mutate()
			if err := validateRuntimeConfiguration(); err == nil {
				t.Fatal("unsafe runtime substitution was accepted")
			}
		})
	}
}

func TestDownloadMutationBudgetIsOneShot(t *testing.T) {
	available := true
	if !consumeDownloadBudget(&available) || available {
		t.Fatal("first Download budget use was rejected")
	}
	if consumeDownloadBudget(&available) || consumeDownloadBudget(nil) {
		t.Fatal("Download budget was reusable")
	}
}

func TestOwnedDownloadRequestShape(t *testing.T) {
	const canaryURL = "https://example.invalid/v1/goproxy/session/github.com/benr00t3d/go-byteman-crosswrite-canary/@v/v0.0.1.zip"
	request := buildTargetDownloadRequest(canaryURL)
	decoded, valid := decodeWireMessage(request, 0)
	if !valid {
		t.Fatalf("request did not decode: %x", request)
	}
	if len(decoded.fields) != 5 {
		t.Fatalf("request field count = %d, want 5: %x", len(decoded.fields), request)
	}
	if decoded.fields[0].number != 1 || decoded.fields[0].wire != 2 || string(decoded.fields[0].value) != canaryURL {
		t.Fatalf("URL field = %#v", decoded.fields[0])
	}
	if decoded.fields[1].number != 4 || decoded.fields[1].wire != 2 {
		t.Fatalf("metadata field = %#v", decoded.fields[1])
	}
	metadata, valid := decodeWireMessage(decoded.fields[1].value, 0)
	if !valid || !targetMetadataMatches(metadata) || len(metadata.fields) != 5 {
		t.Fatalf("metadata = %#v, valid=%t", metadata, valid)
	}
	if decoded.fields[2].number != 5 || decoded.fields[2].wire != 0 || decoded.fields[2].varint != downloadPolicyOnlyNew {
		t.Fatalf("ONLY_NEW policy field = %#v", decoded.fields[2])
	}
	if decoded.fields[3].number != 6 || decoded.fields[3].wire != 2 || string(decoded.fields[3].value) != downloadSource {
		t.Fatalf("source field = %#v", decoded.fields[3])
	}
	if decoded.fields[4].number != 8 || decoded.fields[4].wire != 2 {
		t.Fatalf("redirect config field = %#v", decoded.fields[4])
	}
	redirect, valid := decodeWireMessage(decoded.fields[4].value, 0)
	if !valid || len(redirect.fields) != 1 || redirect.fields[0].number != 1 ||
		redirect.fields[0].wire != 0 || redirect.fields[0].varint != redirectFollowNone {
		t.Fatalf("FOLLOW_NONE redirect policy = %#v, valid=%t", redirect, valid)
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
	record = appendVarintField(record, 5, downloadHTTPStatus)
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
		t.Fatalf("one empty streaming Lookup frame = %#v, err %v", empty, err)
	}
	if _, err := analyzeLookupBody(nil); err == nil {
		t.Fatal("zero-frame streaming Lookup response was accepted")
	}
	twoEmpty, err := analyzeLookupBody(append(grpcTestFrame(nil), grpcTestFrame(nil)...))
	if err != nil || twoEmpty.RecordCount != 0 {
		t.Fatalf("two empty streaming Lookup frames = %#v, err %v", twoEmpty, err)
	}
}

func TestLookupDecoderAggregatesOrderedServerStreamFrames(t *testing.T) {
	prior := bytemanCanaryURL
	bytemanCanaryURL = "https://example.invalid/owned-b.zip"
	defer func() { bytemanCanaryURL = prior }()
	nonmatch := targetLookupRecord("https://example.invalid/other.zip")
	target := targetLookupRecord(bytemanCanaryURL)
	body := grpcTestFrame(appendBytesField(nil, 1, nonmatch))
	body = append(body, grpcTestFrame(nil)...)
	body = append(body, grpcTestFrame(appendBytesField(nil, 1, target))...)
	analysis, err := analyzeLookupBody(body)
	if err != nil || analysis.RecordCount != 2 || analysis.MatchCount != 1 ||
		analysis.MatchPath != "frame[2].1[0]" || analysis.RecordsSHA256 == "" || analysis.MatchSHA256 == "" {
		t.Fatalf("streaming Lookup aggregation = %#v, err %v", analysis, err)
	}
	reversed := grpcTestFrame(appendBytesField(nil, 1, target))
	reversed = append(reversed, grpcTestFrame(appendBytesField(nil, 1, nonmatch))...)
	reversedAnalysis, err := analyzeLookupBody(reversed)
	if err != nil || reversedAnalysis.RecordsSHA256 == analysis.RecordsSHA256 {
		t.Fatalf("ordered stream record digest was not order-sensitive: %#v, err %v", reversedAnalysis, err)
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

func TestTargetMetadataRejectsUnknownAndDuplicateFields(t *testing.T) {
	base, valid := decodeWireMessage(buildTargetMetadata(), 0)
	if !valid || !targetMetadataMatches(base) {
		t.Fatal("fixed B metadata was rejected")
	}
	unknown, valid := decodeWireMessage(appendStringField(buildTargetMetadata(), 7, "substitute"), 0)
	if !valid || targetMetadataMatches(unknown) {
		t.Fatal("unknown metadata field was accepted")
	}
	duplicate, valid := decodeWireMessage(appendStringField(buildTargetMetadata(), 4, targetModuleName), 0)
	if !valid || targetMetadataMatches(duplicate) {
		t.Fatal("duplicate B name was accepted")
	}
	withSystem, valid := decodeWireMessage(appendVarintField(buildTargetMetadata(), 1, 7), 0)
	if !valid || !targetMetadataMatches(withSystem) {
		t.Fatal("single optional legacy system enum was rejected")
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
	missingID = appendVarintField(missingID, 5, downloadHTTPStatus)
	metadata := appendStringField(nil, 2, targetRegistry)
	metadata = appendVarintField(metadata, 3, 1)
	metadata = appendStringField(metadata, 4, targetModuleName)
	metadata = appendVarintField(metadata, 5, 1)
	metadata = appendStringField(metadata, 6, targetVersion)
	missingID = appendBytesField(missingID, 12, metadata)
	missingIDResponse := appendBytesField(nil, 1, missingID)
	missingIDResponse = appendVarintField(missingIDResponse, 3, downloadHTTPStatus)
	if _, err := analyzeDownloadBody(grpcTestFrame(missingIDResponse)); err == nil {
		t.Fatal("DownloadResponse without ID field 17 was accepted")
	}
	if _, err := analyzeDownloadBody(grpcTestFrame(appendBytesField(nil, 1, record))); err == nil {
		t.Fatal("DownloadResponse without status_code field 3 was accepted")
	}
	badResponseStatus := appendBytesField(nil, 1, record)
	badResponseStatus = appendVarintField(badResponseStatus, 3, 500)
	if _, err := analyzeDownloadBody(grpcTestFrame(badResponseStatus)); err == nil {
		t.Fatal("DownloadResponse with non-success status_code was accepted")
	}
	recordWithoutStatus := appendStringField(nil, 1, bytemanCanaryURL)
	recordWithoutStatus = appendBytesField(recordWithoutStatus, 2, []byte("opaque digest message"))
	recordWithoutStatus = appendVarintField(recordWithoutStatus, 3, targetCanaryBytes)
	recordWithoutStatus = appendBytesField(recordWithoutStatus, 12, metadata)
	recordWithoutStatus = appendBytesField(recordWithoutStatus, 17, []byte("opaque service record id"))
	missingRecordStatus := appendBytesField(nil, 1, recordWithoutStatus)
	missingRecordStatus = appendVarintField(missingRecordStatus, 3, downloadHTTPStatus)
	if _, err := analyzeDownloadBody(grpcTestFrame(missingRecordStatus)); err == nil {
		t.Fatal("Download record without status_code field 5 was accepted")
	}
}

func TestExactLookupPairRequiresReturnedDigestAndID(t *testing.T) {
	base := grpcResult{
		HTTPStatus: http.StatusOK, GRPCStatus: "0", ContentType: "application/grpc", LookupMatchCount: 1,
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

func TestStrictDownloadRequiresGRPCAndBothSuccessStatuses(t *testing.T) {
	base := grpcResult{
		HTTPStatus: http.StatusOK, GRPCStatus: "0", ContentType: "application/grpc",
		RecordMatched: true, DigestFieldSHA256: "digest", IDFieldSHA256: "id",
		DownloadStatusSet: true, DownloadStatusCode: downloadHTTPStatus,
	}
	if !downloadStrictlyAccepted(base) {
		t.Fatal("strict successful Download was rejected")
	}
	for name, mutate := range map[string]func(*grpcResult){
		"wrong-content-type": func(value *grpcResult) { value.ContentType = "text/plain" },
		"missing-status":     func(value *grpcResult) { value.DownloadStatusSet = false },
		"bad-status":         func(value *grpcResult) { value.DownloadStatusCode = 500 },
		"analysis-error":     func(value *grpcResult) { value.AnalysisError = "bad wire" },
		"missing-id":         func(value *grpcResult) { value.IDFieldSHA256 = "" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := base
			mutate(&changed)
			if downloadStrictlyAccepted(changed) {
				t.Fatal("non-strict Download was accepted")
			}
		})
	}
}

func TestOriginOfflineCheckDoesNotConsumeAvailableCanary(t *testing.T) {
	priorURL := bytemanCanaryURL
	priorAgent := probeUserAgent
	defer func() {
		bytemanCanaryURL = priorURL
		probeUserAgent = priorAgent
	}()
	probeUserAgent = expectedUserAgent
	var gets atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("X-Codex-One-Shot-State", "available")
		if request.Method == http.MethodGet {
			gets.Add(1)
		}
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	bytemanCanaryURL = server.URL
	result := verifyOriginOffline()
	if result.Offline || result.HeadHTTPStatus != http.StatusOK || result.HeadState != "available" || gets.Load() != 0 {
		t.Fatalf("available origin check consumed canary: %#v, gets=%d", result, gets.Load())
	}
}

func TestOriginOfflineCheckRequiresConsumedHeadAndExactGoneGet(t *testing.T) {
	priorURL := bytemanCanaryURL
	priorAgent := probeUserAgent
	defer func() {
		bytemanCanaryURL = priorURL
		probeUserAgent = priorAgent
	}()
	probeUserAgent = expectedUserAgent
	var gets atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("X-Codex-One-Shot-State", "consumed")
		writer.WriteHeader(http.StatusGone)
		if request.Method == http.MethodGet {
			gets.Add(1)
			_, _ = writer.Write([]byte(`{"error":"one-shot canary consumed"}`))
		}
	}))
	defer server.Close()
	bytemanCanaryURL = server.URL
	result := verifyOriginOffline()
	if !result.Offline || result.HeadHTTPStatus != http.StatusGone || result.HTTPStatus != http.StatusGone || gets.Load() != 1 {
		t.Fatalf("consumed origin was not proven offline: %#v, gets=%d", result, gets.Load())
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
		"exact-plus-unknown": appendBytesField(
			appendBytesField(nil, 2, payload), 9, []byte("unexpected")),
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
	_, unrelatedRoots := legacyTLSState(t, "localhost")
	if err := verifyLegacyLocalhost(state, unrelatedRoots); err == nil {
		t.Fatal("localhost certificate from an unmounted root was accepted")
	}
}

func TestPlanStepValidation(t *testing.T) {
	valid := []planStep{
		{Version: 1, ID: "inspect", Action: "inspect-session-dataflow"},
		{Version: 1, ID: "direct", Action: "probe-byteman", RouteMode: "byteman-localhost"},
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
		{Version: 1, ID: "core", Action: "probe-byteman", RouteMode: "byteman-core-localhost"},
		{Version: 1, ID: "gateway", Action: "probe-byteman", RouteMode: "byteman-oregon-gateway"},
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
