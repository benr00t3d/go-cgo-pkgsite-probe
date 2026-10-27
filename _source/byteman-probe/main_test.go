package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
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

func TestPinnedStreamRequestShape(t *testing.T) {
	installSyntheticRuntimeConfiguration(t)
	request := buildTargetStreamRequest(bytemanCanaryURL)
	if len(bytemanCanaryURL) != 188 || len(buildTargetMetadata()) != 89 || len(request) != 282 {
		t.Fatalf("URL/metadata/request bytes = %d/%d/%d", len(bytemanCanaryURL), len(buildTargetMetadata()), len(request))
	}
	message, valid := decodeWireMessage(request, 0)
	if !valid || len(message.fields) != 2 || message.fields[0].number != 1 || message.fields[1].number != 2 ||
		string(message.fields[0].value) != bytemanCanaryURL {
		t.Fatalf("StreamRequest fields = %#v", message)
	}
}

func installSyntheticRuntimeConfiguration(t *testing.T) string {
	t.Helper()
	priorGeneric, priorCompiler, priorPlan := genericResultURL, compilerResultURL, planURL
	priorCanary, priorSession, priorAgent := bytemanCanaryURL, sessionNonce, probeUserAgent
	priorPinnedReadbackDigest := pinnedReadbackURLSHA256
	priorField, priorValue, priorName := descriptorDownloadPolicyField, descriptorDownloadPolicyValue, descriptorDownloadPolicyName
	priorRedirectConfig, priorRedirectField := descriptorRedirectConfigField, descriptorRedirectPolicyField
	priorRedirectValue, priorRedirectName := descriptorRedirectPolicyValue, descriptorRedirectPolicyName
	sessionNonce = strings.Repeat("a", 64)
	origin := "https://example.invalid"
	genericResultURL = origin + "/v1/result/" + sessionNonce + "/generic"
	compilerResultURL = origin + "/v1/result/" + sessionNonce + "/compiler"
	planURL = origin + "/v1/plan/" + sessionNonce
	readbackSession := strings.Repeat("b", 64)
	bytemanCanaryURL = "https://" + pinnedReadbackHost + "/v1/goproxy/" + readbackSession + "/" + targetModuleName + "/@v/" + targetVersion + ".zip"
	readbackDigest := sha256.Sum256([]byte(bytemanCanaryURL))
	pinnedReadbackURLSHA256 = hex.EncodeToString(readbackDigest[:])
	probeUserAgent = expectedUserAgent
	descriptorDownloadPolicyField = "5"
	descriptorDownloadPolicyValue = "4"
	descriptorDownloadPolicyName = "ALWAYS"
	descriptorRedirectConfigField = "8"
	descriptorRedirectPolicyField = "1"
	descriptorRedirectPolicyValue = "2"
	descriptorRedirectPolicyName = "FOLLOW_NONE"
	t.Cleanup(func() {
		genericResultURL, compilerResultURL, planURL = priorGeneric, priorCompiler, priorPlan
		bytemanCanaryURL, sessionNonce, probeUserAgent = priorCanary, priorSession, priorAgent
		pinnedReadbackURLSHA256 = priorPinnedReadbackDigest
		descriptorDownloadPolicyField, descriptorDownloadPolicyValue, descriptorDownloadPolicyName = priorField, priorValue, priorName
		descriptorRedirectConfigField, descriptorRedirectPolicyField = priorRedirectConfig, priorRedirectField
		descriptorRedirectPolicyValue, descriptorRedirectPolicyName = priorRedirectValue, priorRedirectName
	})
	return bytemanCanaryURL
}

func TestOwnedDownloadRequestShape(t *testing.T) {
	canaryURL := installSyntheticRuntimeConfiguration(t)
	request, err := buildTargetDownloadRequest(canaryURL)
	if err != nil {
		t.Fatal(err)
	}
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
	decoded, valid := decodeWireMessage(request, 0)
	if !valid {
		t.Fatal("Download request was not valid protobuf wire data")
	}
	policyCount := 0
	redirectCount := 0
	for _, field := range decoded.fields {
		if field.number == 5 && field.wire == 0 && field.varint == 4 {
			policyCount++
		}
		if field.number == 8 && field.wire == 2 && field.child != nil && len(field.child.fields) == 1 &&
			field.child.fields[0].number == 1 && field.child.fields[0].wire == 0 && field.child.fields[0].varint == 2 {
			redirectCount++
		}
	}
	if policyCount != 1 {
		t.Fatalf("descriptor policy count = %d", policyCount)
	}
	if redirectCount != 1 {
		t.Fatalf("descriptor redirect config count = %d", redirectCount)
	}
	transcript := grpcResult{}
	frame := attachRequestTranscript(&transcript, request)
	payloadDigest := sha256.Sum256(request)
	frameDigest := sha256.Sum256(frame)
	if transcript.RequestPayloadBytes != len(request) || transcript.RequestFrameBytes != len(request)+5 ||
		transcript.RequestPayloadSHA256 != hex.EncodeToString(payloadDigest[:]) ||
		transcript.RequestFrameSHA256 != hex.EncodeToString(frameDigest[:]) ||
		transcript.RequestWireError != "" || len(transcript.RequestWire) == 0 {
		t.Fatalf("request transcript = %#v", transcript)
	}
}

func TestDownloadPolicyPatchPointFailsClosed(t *testing.T) {
	canaryURL := installSyntheticRuntimeConfiguration(t)
	descriptorDownloadPolicyField = ""
	descriptorDownloadPolicyValue = ""
	descriptorDownloadPolicyName = ""
	if request, err := buildTargetDownloadRequest(canaryURL); err == nil || request != nil {
		t.Fatalf("unresolved descriptor patch point returned request %x, err %v", request, err)
	}
}

func TestRuntimeConfigurationPinsOriginAndOwnedBPath(t *testing.T) {
	installSyntheticRuntimeConfiguration(t)
	if err := validateRuntimeConfiguration(); err != nil {
		t.Fatalf("valid runtime configuration rejected: %v", err)
	}
	bytemanCanaryURL = strings.Replace(bytemanCanaryURL, targetModuleName, moduleName, 1)
	if err := validateRuntimeConfiguration(); err == nil {
		t.Fatal("executing A coordinate was accepted as the owned-B canary path")
	}
}

func TestRuntimeConfigurationDecouplesCallbackAndPinnedReadbackAuthorities(t *testing.T) {
	installSyntheticRuntimeConfiguration(t)
	callback, _ := url.Parse(genericResultURL)
	readback, _ := url.Parse(bytemanCanaryURL)
	if callback.Host == readback.Host {
		t.Fatal("test fixture did not use independent callback and readback authorities")
	}
	if err := validateRuntimeConfiguration(); err != nil {
		t.Fatalf("independent fixed authorities rejected: %v", err)
	}
	bytemanCanaryURL += "?substitute=1"
	if err := validateRuntimeConfiguration(); err == nil {
		t.Fatal("runtime readback URL substitution was accepted")
	}
}

func TestMutationBudgetAllowsOnlyOneClaim(t *testing.T) {
	budget := &mutationBudget{}
	if !budget.claim() || budget.claim() {
		t.Fatal("session-wide mutation budget did not allow exactly one claim")
	}
}

func TestFixedSOSSessionMetadataShape(t *testing.T) {
	request, err := http.NewRequest(http.MethodPost, "https://example.invalid/sos.byteman.Byteman/Lookup", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set(sosSessionMetadataKey, "")
	values, present := request.Header[http.CanonicalHeaderKey(sosSessionMetadataKey)]
	if !present || len(values) != 1 || values[0] != "" {
		t.Fatalf("fixed session metadata = %#v, present=%t", values, present)
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
		t.Fatalf("one empty streaming Lookup frame = %#v, err %v", empty, err)
	}
	if _, err := analyzeLookupBody(nil); err == nil {
		t.Fatal("zero-frame Lookup response was accepted")
	}
	nonmatch := appendStringField(nil, 1, "https://example.invalid/not-owned-b.zip")
	multi := append(grpcTestFrame(appendBytesField(nil, 1, nonmatch)), grpcTestFrame(response)...)
	streamed, err := analyzeLookupBody(multi)
	if err != nil || streamed.RecordCount != 2 || streamed.MatchCount != 1 || streamed.MatchPath != "frame[1].1[0]" {
		t.Fatalf("multi-frame streaming Lookup = %#v, err %v", streamed, err)
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
	if !exactLookupPair(base, base, "", "") {
		t.Fatal("identical service-established pair was rejected during ambiguous-response recovery")
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

type failAfterReader struct {
	reader *bytes.Reader
}

func (reader *failAfterReader) Read(destination []byte) (int, error) {
	if reader.reader.Len() == 0 {
		return 0, errors.New("reader was accessed after the exact payload")
	}
	return reader.reader.Read(destination)
}

func TestIncrementalStreamStopsBeforeEOFAfterExactPayload(t *testing.T) {
	installSyntheticRuntimeConfiguration(t)
	payload, err := os.ReadFile("testdata/v0.0.1-crosswrite-canary.zip")
	if err != nil {
		t.Fatal(err)
	}
	rawHeader := appendStringField(nil, 1, "Content-Length")
	rawHeader = appendBytesField(rawHeader, 2, []byte("2512"))
	header := appendStringField(nil, 1, "application/zip")
	header = appendVarintField(header, 2, http.StatusOK)
	header = appendStringField(header, 3, "owned-b-etag")
	header = appendBytesField(header, 9, rawHeader)
	message0 := appendBytesField(nil, 1, header)
	message0 = appendBytesField(message0, 2, payload[:101])
	message1 := appendBytesField(nil, 2, payload[101:1700])
	message2 := appendBytesField(nil, 2, payload[1700:])
	body := append(grpcTestFrame(message0), grpcTestFrame(message1)...)
	body = append(body, grpcTestFrame(message2)...)
	analysis, err := readExactStreamFrames(&failAfterReader{reader: bytes.NewReader(body)})
	if err != nil {
		t.Fatal(err)
	}
	if analysis.FrameCount != 3 || analysis.BodyBytes != len(body) || len(analysis.FrameSHA256) != 3 ||
		analysis.PayloadSHA256 != targetCanarySHA256 || len(analysis.Payload) != targetCanaryBytes ||
		analysis.HeaderCount != 1 || !analysis.Header.Valid || analysis.Header.StatusCode != http.StatusOK ||
		analysis.Header.ContentType != "application/zip" || analysis.Header.RawCount != 1 || analysis.HeaderSHA256 == "" {
		t.Fatalf("incremental analysis = %#v", analysis)
	}
}

func TestIncrementalStreamRejectsInvalidFrames(t *testing.T) {
	payload, err := os.ReadFile("testdata/v0.0.1-crosswrite-canary.zip")
	if err != nil {
		t.Fatal(err)
	}
	validHeader := appendVarintField(nil, 2, http.StatusOK)
	validMessage := appendBytesField(nil, 1, validHeader)
	validMessage = appendBytesField(validMessage, 2, payload)
	compressed := grpcTestFrame(validMessage)
	compressed[0] = 1
	wrongHashPayload := append([]byte(nil), payload...)
	wrongHashPayload[0] ^= 0xff
	tests := map[string][]byte{
		"compressed":       compressed,
		"unexpected-field": grpcTestFrame(appendBytesField(nil, 9, payload)),
		"overrun":          grpcTestFrame(appendBytesField(nil, 2, append(payload, 0))),
		"wrong-hash":       grpcTestFrame(appendBytesField(nil, 2, wrongHashPayload)),
		"premature-eof":    grpcTestFrame(appendBytesField(nil, 2, payload[:100])),
		"missing-header":   grpcTestFrame(appendBytesField(nil, 2, payload)),
		"wrong-status":     grpcTestFrame(append(appendBytesField(nil, 1, appendVarintField(nil, 2, 404)), appendBytesField(nil, 2, payload)...)),
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := readExactStreamFrames(bytes.NewReader(body)); err == nil {
				t.Fatal("invalid incremental Stream body was accepted")
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

func TestMountedPrivateRootPoolContainsOnlyMountedRoots(t *testing.T) {
	state, _ := legacyTLSState(t, "localhost")
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: state.PeerCertificates[1].Raw})
	roots, err := mountedPrivateRootPool(rootPEM)
	if err != nil {
		t.Fatal(err)
	}
	if subjects := roots.Subjects(); len(subjects) != 1 {
		t.Fatalf("mounted-only root subjects = %d, want 1", len(subjects))
	}
	if _, err := mountedPrivateRootPool([]byte("not a certificate")); err == nil {
		t.Fatal("invalid mounted root pool was accepted")
	}
}

func TestPlanStepValidation(t *testing.T) {
	valid := []planStep{
		{Version: 1, ID: "stream", Action: "stream-existing-v44", RouteMode: "byteman-localhost"},
		{Version: 1, ID: "done", Action: "finish"},
	}
	for _, step := range valid {
		if err := validatePlanStep(step); err != nil {
			t.Fatalf("valid step rejected: %v", err)
		}
	}
	invalid := []planStep{
		{Version: 1, ID: "shell", Action: "exec", RouteMode: "byteman-core-localhost"},
		{Version: 1, ID: "missing-mode", Action: "stream-existing-v44"},
		{Version: 1, ID: "core", Action: "stream-existing-v44", RouteMode: "byteman-core-localhost"},
		{Version: 1, ID: "gateway", Action: "stream-existing-v44", RouteMode: "byteman-oregon-gateway"},
		{Version: 1, ID: "old-probe", Action: "probe-byteman", RouteMode: "byteman-localhost"},
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
