package main

import (
	"bytes"
	"crypto/sha256"
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
	pinnedReadbackOrigin = "https://consumed-origin.example.invalid"
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

func TestRuntimeConfigurationSeparatesCallbackAndPinnedReadback(t *testing.T) {
	installTestConfiguration(t)
	if err := validateRuntimeConfiguration(); err != nil {
		t.Fatalf("valid isolated configuration rejected: %v", err)
	}
	pinnedReadbackOrigin = "https://fresh-callback.example.invalid"
	if err := validateRuntimeConfiguration(); err == nil {
		t.Fatal("callback origin was accepted as the pinned readback origin")
	}
}

func TestStreamRequestPinsURLAndExactMetadata(t *testing.T) {
	installTestConfiguration(t)
	request := buildTargetStreamRequest(true)
	fields, err := decodeWireFields(request)
	if err != nil || len(fields) != 2 {
		t.Fatalf("request fields = %#v, err %v", fields, err)
	}
	if fields[0].number != 1 || fields[0].wire != 2 || string(fields[0].value) != pinnedReadbackURL {
		t.Fatal("Stream URL field did not equal the pinned readback URL")
	}
	if fields[1].number != 2 || fields[1].wire != 2 || !bytes.Equal(fields[1].value, buildTargetMetadata()) {
		t.Fatal("Stream metadata field did not equal exact owned-B metadata")
	}
	metadataDigest := sha256.Sum256(fields[1].value)
	if got := hex.EncodeToString(metadataDigest[:]); got != "d8a03518274139d9b6dbec8b09ce0e6d9ec1ddfc3c9d5a15119ca7c677d85a62" {
		t.Fatalf("metadata SHA256 = %s", got)
	}
	urlOnly := buildTargetStreamRequest(false)
	urlFields, err := decodeWireFields(urlOnly)
	if err != nil || len(urlFields) != 1 || urlFields[0].number != 1 || string(urlFields[0].value) != pinnedReadbackURL {
		t.Fatalf("URL-only fields = %#v, err %v", urlFields, err)
	}
}

func TestStreamTransportHeaderVariantsAreExact(t *testing.T) {
	installTestConfiguration(t)
	for _, present := range []bool{true, false} {
		request, err := http.NewRequest(http.MethodPost, "https://byteman.example.invalid/sos.byteman.Byteman/Stream", nil)
		if err != nil {
			t.Fatal(err)
		}
		applyStreamHeaders(request, present)
		values, found := request.Header["X-Sos-Sessionid"]
		if found != present {
			t.Fatalf("header presence = %t, want %t", found, present)
		}
		if present {
			if len(values) != 1 || values[0] != "" {
				t.Fatalf("X-SOS-SessionID = %#v", values)
			}
			digest := sha256.Sum256([]byte(values[0]))
			if hex.EncodeToString(digest[:]) != emptyValueSHA256 {
				t.Fatal("empty session header digest changed")
			}
		}
	}
}

func TestFixedVariantsStopImmediatelyAfterSuccess(t *testing.T) {
	want := []string{
		"url-metadata-empty-session",
		"url-only-empty-session",
		"url-metadata-session-omitted",
		"url-only-session-omitted",
	}
	called := []string{}
	results, success := runFixedStreamVariants(func(variant streamVariant) streamResult {
		called = append(called, variant.ID)
		return streamResult{VariantID: variant.ID, Verified: len(called) == 2}
	})
	if success != want[1] || len(results) != 2 || !bytes.Equal([]byte(strings.Join(called, "\n")), []byte(strings.Join(want[:2], "\n"))) {
		t.Fatalf("called=%v results=%d success=%q", called, len(results), success)
	}
	for index, variant := range fixedStreamVariants {
		if variant.ID != want[index] {
			t.Fatalf("variant %d = %q", index, variant.ID)
		}
	}
}

func TestGRPCHeadersAndTrailersCapturedWithMessageRedaction(t *testing.T) {
	installTestConfiguration(t)
	header := http.Header{
		"Grpc-Status":  []string{"2"},
		"Grpc-Message": []string{"unable%20to%20open%20" + pinnedReadbackSession},
	}
	status, message := grpcMetadataValue{}, grpcMetadataValue{}
	captureGRPCMetadata(header, &status, &message)
	if !status.Present || status.Text != "2" || !message.Present || !strings.Contains(message.Text, "[redacted]") || strings.Contains(message.Text, pinnedReadbackSession) {
		t.Fatalf("status=%#v message=%#v", status, message)
	}
	result := streamResult{}
	captureGRPCTrailers(&http.Response{Trailer: header}, &result)
	if !result.TrailersObserved || result.GRPCStatusTrailer.Text != "2" || !result.GRPCMessageTrailer.Present {
		t.Fatalf("trailer capture = %#v", result)
	}
}

func TestIncrementalStreamConsumesOnlyTopLevelData(t *testing.T) {
	payload, err := os.ReadFile("testdata/v0.0.1-crosswrite-canary.zip")
	if err != nil {
		t.Fatal(err)
	}
	header := appendStringField(nil, 1, "application/zip")
	header = appendVarintField(header, 2, 200)
	message0 := appendBytesField(nil, 1, header)
	message0 = appendBytesField(message0, 2, payload[:137])
	message1 := appendBytesField(nil, 2, payload[137:1701])
	message2 := appendBytesField(nil, 2, payload[1701:])
	combined := []byte{}
	headerResult := streamHeaderResult{}
	for index, message := range [][]byte{message0, message1, message2} {
		frame := streamFrameResult{Index: index}
		if err := consumeStreamFrame(message, &combined, &headerResult, &frame); err != nil {
			t.Fatal(err)
		}
	}
	digest := sha256.Sum256(combined)
	if len(combined) != targetCanaryBytes || hex.EncodeToString(digest[:]) != targetCanarySHA256 {
		t.Fatal("incremental top-level payload did not match exact canary")
	}
	if !headerResult.Present || !headerResult.StatusSet || headerResult.StatusCode != 200 || headerResult.ContentType != "application/zip" {
		t.Fatalf("header = %#v", headerResult)
	}
	if _, err := verifyCompletedStream(combined, headerResult); err != nil {
		t.Fatalf("complete valid stream rejected: %v", err)
	}
}

func TestCompletedStreamRequiresHeaderStatus200(t *testing.T) {
	payload, err := os.ReadFile("testdata/v0.0.1-crosswrite-canary.zip")
	if err != nil {
		t.Fatal(err)
	}
	for name, header := range map[string]streamHeaderResult{
		"missing":        {},
		"missing-status": {Present: true},
		"wrong-status":   {Present: true, StatusSet: true, StatusCode: 500},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := verifyCompletedStream(payload, header); err == nil {
				t.Fatal("exact payload without exact status 200 header was accepted")
			}
		})
	}
}

func TestStreamRawHeaderUsesPinnedNestedSchema(t *testing.T) {
	raw := appendStringField(nil, 1, "x-test")
	raw = appendBytesField(raw, 2, []byte("value"))
	parsed, err := parseStreamRawHeader(raw)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Name != "x-test" || parsed.ValueBytes != 5 {
		t.Fatalf("raw header = %#v", parsed)
	}
	if _, err := parseStreamRawHeader(appendBytesField(nil, 9, []byte("value"))); err == nil {
		t.Fatal("unknown nested raw-header field was accepted")
	}
}

func TestStreamRejectsNestedOrUnexpectedData(t *testing.T) {
	payload, err := os.ReadFile("testdata/v0.0.1-crosswrite-canary.zip")
	if err != nil {
		t.Fatal(err)
	}
	for name, message := range map[string][]byte{
		"nested":     appendBytesField(nil, 1, appendBytesField(nil, 2, payload)),
		"field-nine": appendBytesField(nil, 9, payload),
		"overrun":    appendBytesField(nil, 2, append(payload, 0)),
	} {
		t.Run(name, func(t *testing.T) {
			combined := []byte{}
			header := streamHeaderResult{}
			frame := streamFrameResult{}
			if err := consumeStreamFrame(message, &combined, &header, &frame); err == nil {
				t.Fatal("invalid StreamResponse was accepted")
			}
		})
	}
}

func TestGRPCFrameIsUncompressedAndExact(t *testing.T) {
	payload := []byte{0x0a, 0x01, 'x'}
	frame := grpcFrame(payload)
	if !bytes.Equal(frame, []byte{0, 0, 0, 0, 3, 0x0a, 0x01, 'x'}) {
		t.Fatalf("frame = %x", frame)
	}
}
