package main

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func installTestConfiguration(t *testing.T) {
	t.Helper()
	priorGeneric, priorCompiler := genericResultURL, compilerResultURL
	priorCallback, priorAgent := callbackSessionNonce, probeUserAgent
	priorURL, priorOrigin := pinnedReadbackURL, pinnedReadbackOrigin
	priorReadbackSession, priorURLSHA := pinnedReadbackSession, pinnedReadbackURLSHA256
	callbackSessionNonce = strings.Repeat("a", 64)
	pinnedReadbackSession = strings.Repeat("b", 64)
	callbackOrigin := "https://fresh-callback.example.invalid"
	pinnedReadbackOrigin = "https://prior-origin.example.invalid"
	genericResultURL = callbackOrigin + "/v1/result/" + callbackSessionNonce + "/generic"
	compilerResultURL = callbackOrigin + "/v1/result/" + callbackSessionNonce + "/compiler"
	pinnedReadbackURL = pinnedReadbackOrigin + "/v1/goproxy/" + pinnedReadbackSession + "/github.com/benr00t3d/go-byteman-crosswrite-canary/@v/v0.0.1.zip"
	digest := sha256.Sum256([]byte(pinnedReadbackURL))
	pinnedReadbackURLSHA256 = hex.EncodeToString(digest[:])
	probeUserAgent = expectedUserAgent
	t.Cleanup(func() {
		genericResultURL, compilerResultURL = priorGeneric, priorCompiler
		callbackSessionNonce, probeUserAgent = priorCallback, priorAgent
		pinnedReadbackURL, pinnedReadbackOrigin = priorURL, priorOrigin
		pinnedReadbackSession, pinnedReadbackURLSHA256 = priorReadbackSession, priorURLSHA
	})
}

func TestRuntimeConfigurationPinsProductionURLDigest(t *testing.T) {
	installTestConfiguration(t)
	fixtureSHA := pinnedReadbackURLSHA256
	if err := validateRuntimeConfigurationWithExpectedSHA(fixtureSHA); err != nil {
		t.Fatalf("valid isolated fixture rejected: %v", err)
	}
	if err := validateRuntimeConfiguration(); err == nil {
		t.Fatal("non-v44 URL digest was accepted")
	}
	pinnedReadbackURLSHA256 = expectedPinnedURLSHA256
	if err := validateRuntimeConfiguration(); err == nil {
		t.Fatal("digest claim inconsistent with URL bytes was accepted")
	}
}

func TestPinnedDownloadRequestIsExact(t *testing.T) {
	installTestConfiguration(t)
	payload := buildPinnedDownloadRequest()
	fields, err := decodeWireFields(payload)
	if err != nil || len(fields) != 4 {
		t.Fatalf("fields=%#v err=%v", fields, err)
	}
	if fields[0].number != 1 || fields[0].wire != 2 || string(fields[0].value) != pinnedReadbackURL ||
		fields[1].number != 4 || fields[1].wire != 2 ||
		fields[2].number != 5 || fields[2].wire != 0 || fields[2].varint != downloadPolicyValue ||
		fields[3].number != 8 || fields[3].wire != 2 {
		t.Fatalf("unexpected request fields: %#v", fields)
	}
	metadataDigest := sha256.Sum256(fields[1].value)
	if hex.EncodeToString(metadataDigest[:]) != expectedMetadataSHA256 || !exactTargetMetadata(fields[1].value) {
		t.Fatal("request metadata was not exact")
	}
	redirect, err := decodeWireFields(fields[3].value)
	if err != nil || len(redirect) != 1 || redirect[0].number != 1 || redirect[0].wire != 0 || redirect[0].varint != redirectPolicyValue {
		t.Fatalf("redirect config=%#v err=%v", redirect, err)
	}
	for _, field := range fields {
		if field.number == 6 || field.number == 7 {
			t.Fatalf("request unexpectedly contained field %d", field.number)
		}
	}
	if downloadPolicyName != "NEVER" || downloadPolicyValue != 1 || redirectPolicyName != "FOLLOW_NONE" || redirectPolicyValue != 2 {
		t.Fatal("descriptor-pinned policy constants changed")
	}
}

func TestDownloadTransportHeadersAndContentTypeAreExact(t *testing.T) {
	request, err := http.NewRequest(http.MethodPost, "https://byteman.example.invalid/sos.byteman.Byteman/Download", nil)
	if err != nil {
		t.Fatal(err)
	}
	applyDownloadHeaders(request)
	values, present := request.Header["X-Sos-Sessionid"]
	if !present || len(values) != 1 || values[0] != "" {
		t.Fatalf("X-SOS-SessionID=%#v present=%t", values, present)
	}
	if request.Header.Get("Grpc-Timeout") != "120S" {
		t.Fatalf("Grpc-Timeout=%q", request.Header.Get("Grpc-Timeout"))
	}
	if !allowedGRPCContentType("application/grpc") || allowedGRPCContentType("application/grpc+proto") || allowedGRPCContentType("application/grpc-evil") {
		t.Fatal("gRPC content type allowlist was not exact")
	}
}

func TestRedirectsAreNeverFollowed(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		writer.Header().Set("Location", serverRedirectTarget(request))
		writer.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	client := &http.Client{CheckRedirect: rejectRedirect}
	response, err := client.Post(server.URL+"/sos.byteman.Byteman/Download", "application/grpc", bytes.NewReader(grpcFrame(nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if requests != 1 || response.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("requests=%d status=%d", requests, response.StatusCode)
	}
}

func TestCallbackTransportHasNoProxyAndRequiresTLS12(t *testing.T) {
	client := newCallbackClient()
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil || transport.TLSClientConfig == nil || transport.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("callback transport=%#v", client.Transport)
	}
}

func serverRedirectTarget(request *http.Request) string {
	return "http://" + request.Host + "/unexpected-alternate"
}

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func fixtureDigest(t *testing.T) []byte {
	t.Helper()
	value := appendBytesField(nil, 1, mustHex(t, targetSHA512))
	value = appendBytesField(value, 2, mustHex(t, targetSHA256))
	value = appendBytesField(value, 3, mustHex(t, targetSHA1))
	return appendBytesField(value, 4, mustHex(t, targetMD5))
}

func fixtureMetadata() []byte {
	return buildTargetMetadata()
}

func fixtureRecord(t *testing.T, rawURL string, status uint64) ([]byte, recordExpectation) {
	t.Helper()
	path, id := []byte("/private/test/path"), []byte("owned-test-record-id")
	record := appendStringField(nil, 1, rawURL)
	record = appendBytesField(record, 2, fixtureDigest(t))
	record = appendVarintField(record, 3, targetCanaryBytes)
	record = appendStringField(record, 4, "application/zip")
	record = appendVarintField(record, 5, status)
	record = appendStringField(record, 7, "no-store")
	record = appendBytesField(record, 12, fixtureMetadata())
	record = appendBytesField(record, 16, path)
	record = appendBytesField(record, 17, id)
	for index := 0; index < 8; index++ {
		header := appendStringField(nil, 1, "x-test-"+string(rune('a'+index)))
		header = appendBytesField(header, 2, []byte{byte(index)})
		record = appendBytesField(record, 18, header)
	}
	recordDigest := sha256.Sum256(record)
	urlDigest := sha256.Sum256([]byte(rawURL))
	digestDigest := sha256.Sum256(fixtureDigest(t))
	pathDigest := sha256.Sum256(path)
	idDigest := sha256.Sum256(id)
	return record, recordExpectation{
		URL: rawURL, URLSHA256: hex.EncodeToString(urlDigest[:]),
		RecordSHA256:      hex.EncodeToString(recordDigest[:]),
		DigestFieldSHA256: hex.EncodeToString(digestDigest[:]),
		PathFieldSHA256:   hex.EncodeToString(pathDigest[:]),
		IDFieldSHA256:     hex.EncodeToString(idDigest[:]),
	}
}

func fixtureResponse(t *testing.T, outerStatus uint64) ([]byte, recordExpectation) {
	t.Helper()
	record, expectation := fixtureRecord(t, "https://owned.example.invalid/v0.0.1.zip", 200)
	payload := appendBytesField(nil, 1, record)
	return appendVarintField(payload, 3, outerStatus), expectation
}

func mustRecordFromResponse(t *testing.T, payload []byte) []byte {
	t.Helper()
	fields, err := decodeWireFields(payload)
	if err != nil || len(fields) < 1 || fields[0].number != 1 {
		t.Fatalf("fixture response fields=%#v err=%v", fields, err)
	}
	return fields[0].value
}

func TestExactDownloadResponseRequiresRecordAndOuterStatus(t *testing.T) {
	payload, expectation := fixtureResponse(t, 200)
	analysis, err := parseDownloadResponse(payload, expectation)
	if err != nil || !analysis.RecordPresent || !analysis.RecordMatched || !analysis.Record.Matched ||
		!analysis.StatusSet || analysis.StatusCode != 200 || !analysis.Record.Digest.AllExact ||
		!analysis.Record.PathPresent || !analysis.Record.IDPresent || analysis.Record.HeaderCount != 8 {
		t.Fatalf("analysis=%#v err=%v", analysis, err)
	}

	missingStatus := appendBytesField(nil, 1, mustRecordFromResponse(t, payload))
	analysis, err = parseDownloadResponse(missingStatus, expectation)
	if err != nil || !analysis.RecordMatched || analysis.StatusSet {
		t.Fatalf("missing outer status analysis=%#v err=%v", analysis, err)
	}
	wrongStatus, _ := fixtureResponse(t, 500)
	analysis, err = parseDownloadResponse(wrongStatus, expectation)
	if err != nil || !analysis.StatusSet || analysis.StatusCode != 500 {
		t.Fatalf("wrong outer status analysis=%#v err=%v", analysis, err)
	}
}

func TestDownloadResponseRejectsUnknownDuplicateAndMismatch(t *testing.T) {
	payload, expectation := fixtureResponse(t, 200)
	record := mustRecordFromResponse(t, payload)
	for name, candidate := range map[string][]byte{
		"unknown":          appendBytesField(append([]byte(nil), payload...), 9, []byte("x")),
		"duplicate-record": appendBytesField(append([]byte(nil), payload...), 1, record),
		"duplicate-status": appendVarintField(append([]byte(nil), payload...), 3, 200),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseDownloadResponse(candidate, expectation); err == nil {
				t.Fatal("invalid DownloadResponse accepted")
			}
		})
	}
	other, _ := fixtureRecord(t, "https://different-owned.example.invalid/v0.0.1.zip", 200)
	mismatch := appendVarintField(appendBytesField(nil, 1, other), 3, 200)
	analysis, err := parseDownloadResponse(mismatch, expectation)
	if err != nil || analysis.RecordMatched || analysis.Record.RecordSHA256 == "" {
		t.Fatalf("mismatch analysis=%#v err=%v", analysis, err)
	}
}

func TestUnaryDownloadReaderRequiresExactlyOneCompleteFrame(t *testing.T) {
	payload, expectation := fixtureResponse(t, 200)
	frame := grpcFrame(payload)
	parsed, err := readUnaryDownloadBody(bytes.NewReader(frame), expectation)
	if err != nil || !parsed.FramePresent || !parsed.EOFObserved || !parsed.Analysis.RecordMatched || parsed.Analysis.StatusCode != 200 {
		t.Fatalf("parsed=%#v err=%v", parsed, err)
	}
	for name, wire := range map[string][]byte{
		"zero":         nil,
		"two":          append(append([]byte(nil), frame...), frame...),
		"truncated":    frame[:len(frame)-1],
		"partial-next": append(append([]byte(nil), frame...), 0),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := readUnaryDownloadBody(bytes.NewReader(wire), expectation); err == nil {
				t.Fatal("invalid unary response accepted")
			}
		})
	}
	compressed := append([]byte(nil), frame...)
	compressed[0] = 1
	if _, err := readUnaryDownloadBody(bytes.NewReader(compressed), expectation); err == nil {
		t.Fatal("compressed response accepted")
	}
}

func TestGRPCCompletionRequiresExactlyOneStatusZero(t *testing.T) {
	zero := grpcMetadataValue{Present: true, Values: 1, RawBytes: 1, Text: "0"}
	nonzero := grpcMetadataValue{Present: true, Values: 1, RawBytes: 1, Text: "2"}
	if !exactZeroGRPCStatus(grpcMetadataValue{}, zero) || !exactZeroGRPCStatus(zero, grpcMetadataValue{}) {
		t.Fatal("one status zero was rejected")
	}
	pairs := [][2]grpcMetadataValue{
		{},
		{zero, zero},
		{nonzero, {}},
		{{Present: true, Values: 2, RawBytes: 3, Text: "0"}, {}},
	}
	for _, pair := range pairs {
		if exactZeroGRPCStatus(pair[0], pair[1]) {
			t.Fatalf("invalid status pair accepted: %#v", pair)
		}
	}
}

func TestDigestConstantsMatchExactCanary(t *testing.T) {
	payload, err := os.ReadFile("testdata/v0.0.1-crosswrite-canary.zip")
	if err != nil {
		t.Fatal(err)
	}
	sha512Value, sha256Value := sha512.Sum512(payload), sha256.Sum256(payload)
	sha1Value, md5Value := sha1.Sum(payload), md5.Sum(payload)
	if len(payload) != targetCanaryBytes || hex.EncodeToString(sha512Value[:]) != targetSHA512 ||
		hex.EncodeToString(sha256Value[:]) != targetSHA256 || hex.EncodeToString(sha1Value[:]) != targetSHA1 ||
		hex.EncodeToString(md5Value[:]) != targetMD5 {
		t.Fatal("canary digest constants changed")
	}
	digest := fixtureDigest(t)
	rawDigest := sha256.Sum256(digest)
	if hex.EncodeToString(rawDigest[:]) != expectedDigestFieldSHA256 {
		t.Fatal("pinned Digest message fingerprint changed")
	}
}

func TestGRPCMetadataCaptureRedactsPinnedIdentity(t *testing.T) {
	installTestConfiguration(t)
	header := http.Header{"Grpc-Status": {"13"}, "Grpc-Message": {"download%20" + pinnedReadbackSession}}
	status, message := grpcMetadataValue{}, grpcMetadataValue{}
	captureGRPCMetadata(header, &status, &message)
	if status.Text != "13" || !message.Present || strings.Contains(message.Text, pinnedReadbackSession) || !strings.Contains(message.Text, "[redacted]") {
		t.Fatalf("status=%#v message=%#v", status, message)
	}
}

func TestGRPCFrameIsExact(t *testing.T) {
	payload := []byte{0x0a, 0x01, 'x'}
	frame := grpcFrame(payload)
	if !bytes.Equal(frame, []byte{0, 0, 0, 0, 3, 0x0a, 0x01, 'x'}) {
		t.Fatalf("frame=%x", frame)
	}
}
