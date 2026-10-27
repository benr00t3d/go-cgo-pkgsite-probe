package main

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"net/http"
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

func TestCoordinateLookupRequestIsExact(t *testing.T) {
	payload := buildCoordinateLookupRequest()
	fields, err := decodeWireFields(payload)
	if err != nil || len(fields) != 4 {
		t.Fatalf("fields=%#v err=%v", fields, err)
	}
	if fields[0].number != 7 || fields[0].wire != 2 || string(fields[0].value) != targetRegistry ||
		fields[1].number != 8 || fields[1].wire != 2 || string(fields[1].value) != targetModuleName ||
		fields[2].number != 9 || fields[2].wire != 2 || string(fields[2].value) != targetVersion ||
		fields[3].number != 10 || fields[3].wire != 0 || fields[3].varint != lookupRecordLimit {
		t.Fatalf("unexpected request fields: %#v", fields)
	}
}

func TestLookupTransportHeadersAndContentTypeAreExact(t *testing.T) {
	request, err := http.NewRequest(http.MethodPost, "https://byteman.example.invalid/sos.byteman.Byteman/Lookup", nil)
	if err != nil {
		t.Fatal(err)
	}
	applyLookupHeaders(request)
	values, present := request.Header["X-Sos-Sessionid"]
	if !present || len(values) != 1 || values[0] != "" {
		t.Fatalf("X-SOS-SessionID=%#v present=%t", values, present)
	}
	if !allowedGRPCContentType("application/grpc") || allowedGRPCContentType("application/grpc+proto") || allowedGRPCContentType("application/grpc-evil") {
		t.Fatal("gRPC content type allowlist was not exact")
	}
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
	value := appendStringField(nil, 2, targetRegistry)
	value = appendVarintField(value, 3, 1)
	value = appendStringField(value, 4, targetModuleName)
	value = appendVarintField(value, 5, 1)
	return appendStringField(value, 6, targetVersion)
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

func TestExactDownloadRecordRequiresAllIntegrityFields(t *testing.T) {
	record, expectation := fixtureRecord(t, "https://owned.example.invalid/v0.0.1.zip", 200)
	proof, matched, err := analyzeDownloadRecord(record, expectation)
	if err != nil || !matched || !proof.Matched {
		t.Fatalf("matched=%t proof=%#v err=%v", matched, proof, err)
	}
	if proof.Size != targetCanaryBytes || proof.StatusCode != 200 || !proof.Digest.AllExact ||
		!proof.PathPresent || !proof.IDPresent || proof.HeaderCount != 8 {
		t.Fatalf("proof=%#v", proof)
	}
	bad, badExpectation := fixtureRecord(t, expectation.URL, 500)
	if _, _, err := analyzeDownloadRecord(bad, badExpectation); err == nil {
		t.Fatal("status 500 exact record was accepted")
	}
}

func TestIncrementalLookupStopsAtFirstExactRecord(t *testing.T) {
	exact, expectation := fixtureRecord(t, "https://owned.example.invalid/v0.0.1.zip", 200)
	message := appendBytesField(nil, 1, []byte{0xff}) // Nonmatching raw rows are fingerprinted, not schema-decoded.
	message = appendBytesField(message, 1, exact)
	message = appendBytesField(message, 1, []byte{0xfe}) // Entire current frame must still be processed.
	accumulator := lookupAccumulator{MatchFrame: -1, MatchRecord: -1}
	frame := lookupFrameResult{Index: 0, MatchedRecord: -1}
	matched, err := consumeLookupFrame(message, 0, &accumulator, &frame, expectation)
	if err != nil || !matched || accumulator.RecordCount != 3 || accumulator.MatchCount != 1 ||
		accumulator.MatchRecord != 1 || frame.MatchedRecord != 1 {
		t.Fatalf("matched=%t accumulator=%#v frame=%#v err=%v", matched, accumulator, frame, err)
	}
}

func TestLookupRejectsDuplicateMatchAndTrailingTopLevelGarbage(t *testing.T) {
	exact, expectation := fixtureRecord(t, "https://owned.example.invalid/v0.0.1.zip", 200)
	for name, message := range map[string][]byte{
		"duplicate":         appendBytesField(appendBytesField(nil, 1, exact), 1, exact),
		"top-level-garbage": appendBytesField(appendBytesField(nil, 1, exact), 9, []byte("garbage")),
	} {
		t.Run(name, func(t *testing.T) {
			accumulator := lookupAccumulator{MatchFrame: -1, MatchRecord: -1}
			frame := lookupFrameResult{Index: 0, MatchedRecord: -1}
			if _, err := consumeLookupFrame(message, 0, &accumulator, &frame, expectation); err == nil {
				t.Fatal("invalid remainder of current frame was accepted")
			}
		})
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
	header := http.Header{"Grpc-Status": {"13"}, "Grpc-Message": {"lookup%20" + pinnedReadbackSession}}
	status, message := grpcMetadataValue{}, grpcMetadataValue{}
	captureGRPCMetadata(header, &status, &message)
	if status.Text != "13" || !message.Present || strings.Contains(message.Text, pinnedReadbackSession) || !strings.Contains(message.Text, "[redacted]") {
		t.Fatalf("status=%#v message=%#v", status, message)
	}
}

func TestGRPCFrameIsExact(t *testing.T) {
	payload := []byte{0x3a, 0x01, 'x'}
	frame := grpcFrame(payload)
	if !bytes.Equal(frame, []byte{0, 0, 0, 0, 3, 0x3a, 0x01, 'x'}) {
		t.Fatalf("frame=%x", frame)
	}
}
