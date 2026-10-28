package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

type testField struct {
	number int
	wire   int
	value  []byte
}

func decodeTestFields(t *testing.T, data []byte) []testField {
	t.Helper()
	fields := []testField{}
	for offset := 0; offset < len(data); {
		key, width := binary.Uvarint(data[offset:])
		if width <= 0 {
			t.Fatal("invalid field key")
		}
		offset += width
		field := testField{number: int(key >> 3), wire: int(key & 7)}
		if field.wire != 2 {
			t.Fatalf("unexpected wire type %d", field.wire)
		}
		length, width := binary.Uvarint(data[offset:])
		if width <= 0 {
			t.Fatal("invalid field length")
		}
		offset += width
		if length > uint64(len(data)-offset) {
			t.Fatal("field exceeds payload")
		}
		field.value = append([]byte(nil), data[offset:offset+int(length)]...)
		offset += int(length)
		fields = append(fields, field)
	}
	return fields
}

func splitTestFrames(t *testing.T, data []byte) [][]byte {
	t.Helper()
	frames := [][]byte{}
	for offset := 0; offset < len(data); {
		if len(data)-offset < 5 || data[offset] != 0 {
			t.Fatal("invalid gRPC frame")
		}
		length := int(binary.BigEndian.Uint32(data[offset+1 : offset+5]))
		offset += 5
		if length > len(data)-offset {
			t.Fatal("truncated gRPC frame")
		}
		frames = append(frames, append([]byte(nil), data[offset:offset+length]...))
		offset += length
	}
	return frames
}

func TestCleanPushWireImageIsPinned(t *testing.T) {
	request := buildCleanPush()
	digest := sha256.Sum256(request)
	if len(request) != expectedPushBytes || hex.EncodeToString(digest[:]) != expectedPushSHA256 {
		t.Fatalf("request bytes=%d sha256=%s", len(request), hex.EncodeToString(digest[:]))
	}
	frames := splitTestFrames(t, request)
	if len(frames) != 2 {
		t.Fatalf("frames=%d", len(frames))
	}
	queueOuter := decodeTestFields(t, frames[0])
	if len(queueOuter) != 1 || queueOuter[0].number != 1 {
		t.Fatalf("queue outer=%#v", queueOuter)
	}
	metadata := decodeTestFields(t, queueOuter[0].value)
	if len(metadata) != 2 || metadata[0].number != 1 || string(metadata[0].value) != queueName ||
		metadata[1].number != 4 || string(metadata[1].value) != queueSource {
		t.Fatalf("metadata=%#v", metadata)
	}
	pushOuter := decodeTestFields(t, frames[1])
	if len(pushOuter) != 1 || pushOuter[0].number != 1 {
		t.Fatalf("push outer=%#v", pushOuter)
	}
	result := decodeTestFields(t, pushOuter[0].value)
	if len(result) != 1 || result[0].number != 3 {
		t.Fatalf("result=%#v", result)
	}
	action := decodeTestFields(t, result[0].value)
	if len(action) != 1 || action[0].number != 1 || string(action[0].value) != targetCoordinate {
		t.Fatalf("action=%#v", action)
	}
}

func TestPrecheckClassificationRequiresOneExactState(t *testing.T) {
	for _, state := range []string{"clean", "altered"} {
		samples := []publicSample{{State: state}, {State: state}, {State: state}}
		got, err := classifyPublicSamples(samples)
		if err != nil || got != state {
			t.Fatalf("state=%s got=%s err=%v", state, got, err)
		}
	}
	if got, err := classifyPublicSamples([]publicSample{{State: "altered"}, {State: "clean"}}); err == nil || got != "mixed" {
		t.Fatalf("mixed got=%s err=%v", got, err)
	}
	if got, err := classifyPublicSamples([]publicSample{{State: "unknown"}}); err == nil || got != "unknown" {
		t.Fatalf("unknown got=%s err=%v", got, err)
	}
}

func TestPublicHashesMapOnlyToPinnedStates(t *testing.T) {
	if publicStateForDigest(cleanSHA256) != "clean" || publicStateForDigest(alteredSHA256) != "altered" {
		t.Fatal("pinned state mapping changed")
	}
	if publicStateForDigest(strings.Repeat("0", 64)) != "unknown" {
		t.Fatal("unknown digest accepted")
	}
}

func TestRuntimeConfigurationPinsOwnedFunction(t *testing.T) {
	priorURL, priorSession, priorSHA := callbackBaseURL, callbackSession, callbackURLSHA256
	callbackSession = strings.Repeat("a", 64)
	callbackBaseURL = "https://us-central1-s0victim-44547.cloudfunctions.net/go-cgo-v121-queue-codex/v1/session/" + callbackSession
	digest := sha256.Sum256([]byte(callbackBaseURL))
	callbackURLSHA256 = hex.EncodeToString(digest[:])
	t.Cleanup(func() { callbackBaseURL, callbackSession, callbackURLSHA256 = priorURL, priorSession, priorSHA })
	if err := validateRuntimeConfiguration(); err != nil {
		t.Fatal(err)
	}
	callbackBaseURL += "/extra"
	if err := validateRuntimeConfiguration(); err == nil {
		t.Fatal("non-exact callback path accepted")
	}
}

func TestGRPCResponseShapeRequiresCompleteFrames(t *testing.T) {
	valid := append(grpcFrame([]byte("one")), grpcFrame([]byte("two"))...)
	if count, ok := countGRPCFrames(valid); !ok || count != 2 {
		t.Fatalf("valid count=%d ok=%t", count, ok)
	}
	if _, ok := countGRPCFrames(valid[:len(valid)-1]); ok {
		t.Fatal("truncated frame accepted")
	}
	if count, ok := countGRPCFrames(nil); ok || count != 0 {
		t.Fatalf("empty count=%d ok=%t", count, ok)
	}
}

func TestGRPCStatusMustBeExactlyOneZero(t *testing.T) {
	zero := grpcMetadata{Present: true, Values: 1, Text: "0"}
	empty := grpcMetadata{}
	if !exactZeroGRPCStatus(empty, zero) || !exactZeroGRPCStatus(zero, empty) {
		t.Fatal("one status zero rejected")
	}
	if exactZeroGRPCStatus(zero, zero) || exactZeroGRPCStatus(empty, empty) ||
		exactZeroGRPCStatus(empty, grpcMetadata{Present: true, Values: 1, Text: "7"}) {
		t.Fatal("invalid gRPC status accepted")
	}
}

func TestCallbackAcknowledgementBindsPhaseAndExactBodyHash(t *testing.T) {
	body := []byte(`{"accepted":true,"phase":"queue","sha256":"` + strings.Repeat("a", 64) + `"}`)
	if !validCallbackAck(body, "queue", strings.Repeat("a", 64)) {
		t.Fatal("valid acknowledgement rejected")
	}
	if validCallbackAck(body, "final", strings.Repeat("a", 64)) ||
		validCallbackAck(body, "queue", strings.Repeat("b", 64)) ||
		validCallbackAck([]byte(`{"accepted":true,"phase":"queue","sha256":"`+strings.Repeat("a", 64)+`","extra":1}`), "queue", strings.Repeat("a", 64)) {
		t.Fatal("unbound acknowledgement accepted")
	}
}

func TestActionReceiptContainsHashNotRawIdentifierField(t *testing.T) {
	body := grpcFrame([]byte("prefix 01234567-89ab-cdef-0123-456789abcdef " + targetCoordinate))
	ids := uuidPattern.FindAll(body, -1)
	if len(ids) != 1 || bytesCount(body, []byte(targetCoordinate)) != 1 {
		t.Fatalf("ids=%d target_count=%d", len(ids), bytesCount(body, []byte(targetCoordinate)))
	}
	digest := sha256.Sum256(ids[0])
	receipt := queueReceipt{ActionIDCount: 1, ActionIDSHA256: hex.EncodeToString(digest[:])}
	encoded, err := jsonMarshal(receipt)
	if err != nil || strings.Contains(string(encoded), string(ids[0])) || !strings.Contains(string(encoded), receipt.ActionIDSHA256) {
		t.Fatal("receipt did not redact action identifier")
	}
}

var bytesCount = func(value, sub []byte) int { return strings.Count(string(value), string(sub)) }
var jsonMarshal = func(value any) ([]byte, error) { return json.Marshal(value) }
