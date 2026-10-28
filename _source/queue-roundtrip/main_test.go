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

func TestInputQueueRescanWireImageIsPinned(t *testing.T) {
	request, err := buildMutationPush()
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(request)
	if len(request) != mutationPushBytes || hex.EncodeToString(digest[:]) != mutationPushSHA256 {
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
		metadata[1].number != 4 || string(metadata[1].value) != mutationSource {
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

func TestCorrectedRefreshWireImageIsPinned(t *testing.T) {
	request := buildRefreshFrame()
	digest := sha256.Sum256(request)
	if len(request) != restoreFrameBytes || hex.EncodeToString(digest[:]) != restoreFrameSHA256 {
		t.Fatalf("request bytes=%d sha256=%s", len(request), hex.EncodeToString(digest[:]))
	}
	frames := splitTestFrames(t, request)
	if len(frames) != 1 {
		t.Fatalf("frames=%d", len(frames))
	}
	outer := decodeTestFields(t, frames[0])
	if len(outer) != 1 || outer[0].number != 2 {
		t.Fatalf("outer=%#v", outer)
	}
	capability := decodeTestFields(t, outer[0].value)
	if len(capability) != 2 || capability[0].number != 1 || string(capability[0].value) != targetCoordinate ||
		capability[1].number != 2 || string(capability[1].value) != restoreSource {
		t.Fatalf("capability=%#v", capability)
	}
}

func TestRestoreCallbackPhasesAreExplicit(t *testing.T) {
	for _, phase := range []string{"preflight", "mutation_queue", "mutation_public", "restore_refresh", "restore_public", "final"} {
		if !validCallbackPhase(phase) {
			t.Fatalf("phase %q rejected", phase)
		}
	}
	if validCallbackPhase("restore_retry") {
		t.Fatal("unbounded restore retry phase accepted")
	}
}

func TestProductionCapabilityResultActionOuterAndMapEntryWireImage(t *testing.T) {
	// This vector tests only the v125-proven outer/map-entry schema. The opaque
	// bytes are deliberately not interpreted as a production capability value.
	value := []byte{0xde, 0xad, 0xbe, 0xef}
	action, err := encodeCapabilityResultAction("p@v", []capabilityMapEntry{{Key: "opaque", Value: value}}, "")
	if err != nil {
		t.Fatal(err)
	}
	want, err := hex.DecodeString("0a03704076120e0a066f70617175651204deadbeef")
	if err != nil {
		t.Fatal(err)
	}
	if string(action) != string(want) {
		t.Fatalf("wire=%x want=%x", action, want)
	}
	outer := decodeTestFields(t, action)
	if len(outer) != 2 || outer[0].number != 1 || string(outer[0].value) != "p@v" || outer[1].number != 2 {
		t.Fatalf("outer=%#v", outer)
	}
	entry := decodeTestFields(t, outer[1].value)
	if len(entry) != 2 || entry[0].number != 1 || string(entry[0].value) != "opaque" ||
		entry[1].number != 2 || string(entry[1].value) != string(value) {
		t.Fatalf("entry=%#v", entry)
	}
}

func TestProductionCapabilityResultActionErrorFieldIsThree(t *testing.T) {
	action, err := encodeCapabilityResultAction("p@v", nil, "analysis failed")
	if err != nil {
		t.Fatal(err)
	}
	fields := decodeTestFields(t, action)
	if len(fields) != 2 || fields[0].number != 1 || string(fields[0].value) != "p@v" ||
		fields[1].number != 3 || string(fields[1].value) != "analysis failed" {
		t.Fatalf("fields=%#v", fields)
	}
}

func TestPublicCapslockCapabilityStatsWireHypothesis(t *testing.T) {
	// Public Capslock commit 2ee85fd defines CapabilityStats capability=1,
	// direct_count=3, and transitive_count=4. This candidate is tested only as
	// a decoding hypothesis; it is not evidence for the opaque Talisman value.
	candidate := []byte{0x08, 0x0a, 0x18, 0x01, 0x20, 0x02}
	fields := decodeCandidateVarintFields(t, candidate)
	if len(fields) != 3 || fields[1] != 10 || fields[3] != 1 || fields[4] != 2 {
		t.Fatalf("candidate fields=%v", fields)
	}
}

func decodeCandidateVarintFields(t *testing.T, data []byte) map[int]uint64 {
	t.Helper()
	fields := map[int]uint64{}
	for offset := 0; offset < len(data); {
		key, width := binary.Uvarint(data[offset:])
		if width <= 0 || key&7 != 0 {
			t.Fatal("invalid candidate field key")
		}
		offset += width
		value, width := binary.Uvarint(data[offset:])
		if width <= 0 {
			t.Fatal("invalid candidate field value")
		}
		offset += width
		fields[int(key>>3)] = value
	}
	return fields
}

func TestPrecheckClassificationRequiresOneExactState(t *testing.T) {
	for _, state := range []string{"clean", "mutated"} {
		samples := []publicSample{{State: state}, {State: state}, {State: state}}
		got, err := classifyPublicSamples(samples)
		if err != nil || got != state {
			t.Fatalf("state=%s got=%s err=%v", state, got, err)
		}
	}
	if got, err := classifyPublicSamples([]publicSample{{State: "mutated"}, {State: "clean"}}); err == nil || got != "mixed" {
		t.Fatalf("mixed got=%s err=%v", got, err)
	}
	if got, err := classifyPublicSamples([]publicSample{{State: "unknown"}}); err == nil || got != "unknown" {
		t.Fatalf("unknown got=%s err=%v", got, err)
	}
}

func TestConvergenceReceiptRetainsTrailingProofWindowAndTotal(t *testing.T) {
	receipt := emptyConvergenceReceipt("mutated")
	for sequence := 1; sequence <= 450; sequence++ {
		appendConvergenceSample(&receipt, publicSample{Sequence: sequence, State: "clean"})
	}
	if receipt.TotalSamples != 450 || len(receipt.Samples) != convergenceSamples {
		t.Fatalf("total=%d retained=%d", receipt.TotalSamples, len(receipt.Samples))
	}
	if receipt.Samples[0].Sequence != 430 || receipt.Samples[len(receipt.Samples)-1].Sequence != 450 {
		t.Fatalf("retained sequence range=%d..%d", receipt.Samples[0].Sequence, receipt.Samples[len(receipt.Samples)-1].Sequence)
	}
}

func TestPublicHashesMapOnlyToPinnedStates(t *testing.T) {
	if publicStateForDigest(cleanSHA256) != "clean" {
		t.Fatal("clean state mapping changed")
	}
	if publicStateForDigest(mutatedSHA256) != "mutated" {
		t.Fatal("suppressed state mapping changed")
	}
	if publicStateForDigest(strings.Repeat("0", 64)) != "unknown" {
		t.Fatal("unknown digest accepted")
	}
}

func TestRuntimeConfigurationPinsOwnedFunction(t *testing.T) {
	priorURL, priorSession, priorSHA := callbackBaseURL, callbackSession, callbackURLSHA256
	callbackSession = strings.Repeat("a", 64)
	callbackBaseURL = "https://us-central1-s0victim-44547.cloudfunctions.net/go-cgo-v130-capability-rescan-codex/v1/session/" + callbackSession
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

func TestStaticPinsAcceptObservedCanonicalBaseline(t *testing.T) {
	if err := validateStaticPins(); err != nil {
		t.Fatal(err)
	}
	request, err := buildMutationPush()
	if err != nil || !matchesRequestPin(request, mutationPushBytes, mutationPushSHA256) {
		t.Fatal("rescan request does not match its independent pin")
	}
}

func TestGRPCResponseShapeRequiresCompleteFrames(t *testing.T) {
	valid := append(grpcFrame([]byte("one")), grpcFrame([]byte("two"))...)
	if count, ok := exactQueueResponseFrames(valid); !ok || count != 2 {
		t.Fatalf("valid count=%d ok=%t", count, ok)
	}
	if _, ok := exactQueueResponseFrames(valid[:len(valid)-1]); ok {
		t.Fatal("truncated frame accepted")
	}
	if count, ok := exactQueueResponseFrames(grpcFrame([]byte("one"))); ok || count != 1 {
		t.Fatalf("one frame count=%d ok=%t", count, ok)
	}
	if count, ok := exactQueueResponseFrames(nil); ok || count != 0 {
		t.Fatalf("empty count=%d ok=%t", count, ok)
	}
}

func TestGRPCStatusMustBeExactlyOneZero(t *testing.T) {
	digest := sha256.Sum256([]byte("0"))
	zero := grpcMetadata{Present: true, Values: 1, RawBytes: 1, RawSHA256: hex.EncodeToString(digest[:]), Text: "0"}
	empty := grpcMetadata{}
	if !exactZeroGRPCStatus(empty, zero) {
		t.Fatal("exact trailer status zero rejected")
	}
	if exactZeroGRPCStatus(zero, zero) || exactZeroGRPCStatus(zero, empty) || exactZeroGRPCStatus(empty, empty) ||
		exactZeroGRPCStatus(empty, grpcMetadata{Present: true, Values: 1, RawBytes: 1, Text: "7"}) {
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

func TestCallbackPhaseSetMatchesSuppressionStateMachine(t *testing.T) {
	for _, phase := range []string{"preflight", "mutation_queue", "mutation_public", "final"} {
		if !validCallbackPhase(phase) {
			t.Fatalf("rescan phase %q rejected", phase)
		}
	}
	for _, phase := range []string{"", "queue", "mutation", "cleanup", "cleanup_queue", "unknown"} {
		if validCallbackPhase(phase) {
			t.Fatalf("unknown phase %q accepted", phase)
		}
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
