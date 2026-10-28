package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

func TestResultRequestWireImageIsPinnedAndDecoded(t *testing.T) {
	request := buildResultRequest()
	digest := sha256.Sum256(request)
	if len(request) != expectedRequestBytes || hex.EncodeToString(digest[:]) != expectedRequestSHA256 {
		t.Fatalf("request bytes=%d sha256=%s", len(request), hex.EncodeToString(digest[:]))
	}
	frames, ok := splitGRPCFrames(request)
	if !ok || len(frames) != 1 {
		t.Fatalf("frames=%d ok=%t", len(frames), ok)
	}
	outer, err := decodeLengthFields(frames[0])
	if err != nil || len(outer) != 1 || outer[0].Number != 2 {
		t.Fatalf("outer=%#v err=%v", outer, err)
	}
	capability, err := decodeLengthFields(outer[0].Value)
	if err != nil || len(capability) != 1 || capability[0].Number != 1 || string(capability[0].Value) != targetCoordinate {
		t.Fatalf("capability=%#v err=%v", capability, err)
	}
	if err := validateStaticPins(); err != nil {
		t.Fatal(err)
	}
}

func encodedEntry(key string, value []byte) []byte {
	entry := appendStringField(nil, 1, key)
	return appendBytesField(entry, 2, value)
}

func encodedResponse(entries ...[]byte) []byte {
	capability := []byte{}
	for _, entry := range entries {
		capability = appendBytesField(capability, 1, entry)
	}
	capability = appendBytesField(capability, 2, []byte{0x08, 0x01})
	return appendBytesField(nil, 2, capability)
}

func TestParseResultResponseHashesAndSortsOwnedEntries(t *testing.T) {
	valueA := []byte{0x08, 0x09, 0x18, 0x01}
	valueB := []byte{0x08, 0x0a, 0x18, 0x07}
	payload := encodedResponse(
		encodedEntry("CAPABILITY_CGO", valueB),
		encodedEntry("CAPABILITY_ARBITRARY_EXECUTION", valueA),
	)
	entries, refreshed, err := parseResultResponse(payload)
	if err != nil || len(entries) != 2 || len(refreshed) != 2 {
		t.Fatalf("entries=%#v refreshed=%x err=%v", entries, refreshed, err)
	}
	if entries[0].Key != "CAPABILITY_ARBITRARY_EXECUTION" || entries[1].Key != "CAPABILITY_CGO" {
		t.Fatalf("keys=%#v", entries)
	}
	digest := sha256.Sum256(valueA)
	if entries[0].ValueBytes != len(valueA) || entries[0].ValueSHA256 != hex.EncodeToString(digest[:]) {
		t.Fatalf("entry=%#v", entries[0])
	}
}

func TestParseResultResponseRejectsAmbiguity(t *testing.T) {
	good := encodedEntry("CAPABILITY_CGO", []byte{1})
	emptyThenKey := appendStringField(nil, 1, "")
	emptyThenKey = appendStringField(emptyThenKey, 1, "CAPABILITY_CGO")
	emptyThenKey = appendBytesField(emptyThenKey, 2, []byte{1})
	emptyThenValue := appendStringField(nil, 1, "CAPABILITY_CGO")
	emptyThenValue = appendBytesField(emptyThenValue, 2, nil)
	emptyThenValue = appendBytesField(emptyThenValue, 2, []byte{1})
	for name, payload := range map[string][]byte{
		"duplicate key":          encodedResponse(good, good),
		"empty value":            encodedResponse(encodedEntry("CAPABILITY_CGO", nil)),
		"empty then valid key":   encodedResponse(emptyThenKey),
		"empty then valid value": encodedResponse(emptyThenValue),
		"bad key":                encodedResponse(encodedEntry("bad key", []byte{1})),
		"wrong outer":            appendBytesField(nil, 1, []byte{1}),
		"truncated":              {0x12, 0x04, 0x0a},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := parseResultResponse(payload); err == nil {
				t.Fatal("ambiguous response accepted")
			}
		})
	}
}

func TestRuntimeConfigurationPinsOwnedFunction(t *testing.T) {
	priorURL, priorSession, priorSHA := callbackBaseURL, callbackSession, callbackURLSHA256
	callbackSession = strings.Repeat("a", 64)
	callbackBaseURL = "https://us-central1-s0victim-44547.cloudfunctions.net/go-cgo-v126-talisman-result-codex/v1/session/" + callbackSession
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

func TestDefaultBuildIsExecutionLocked(t *testing.T) {
	if err := validateRuntimeConfiguration(); err == nil {
		t.Fatal("unconfigured client unexpectedly executable")
	}
}

func TestGRPCStatusMustBeExactTrailerZero(t *testing.T) {
	digest := sha256.Sum256([]byte("0"))
	zero := grpcMetadata{Present: true, Values: 1, RawBytes: 1, RawSHA256: hex.EncodeToString(digest[:]), Text: "0"}
	empty := grpcMetadata{}
	if !exactZeroGRPCStatus(empty, zero) {
		t.Fatal("exact trailer zero rejected")
	}
	if exactZeroGRPCStatus(zero, empty) || exactZeroGRPCStatus(zero, zero) ||
		exactZeroGRPCStatus(empty, grpcMetadata{Present: true, Values: 1, RawBytes: 1, Text: "7"}) {
		t.Fatal("invalid gRPC status accepted")
	}
}

func TestCallbackAcknowledgementBindsPhaseAndBodyHash(t *testing.T) {
	body := []byte(`{"accepted":true,"phase":"result","sha256":"` + strings.Repeat("a", 64) + `"}`)
	if !validCallbackAck(body, "result", strings.Repeat("a", 64)) {
		t.Fatal("valid acknowledgement rejected")
	}
	if validCallbackAck(body, "preflight", strings.Repeat("a", 64)) ||
		validCallbackAck(body, "result", strings.Repeat("b", 64)) {
		t.Fatal("unbound acknowledgement accepted")
	}
}

func TestPrivateResponseIsBoundToReceiptHash(t *testing.T) {
	raw := grpcFrame(encodedResponse(encodedEntry("CAPABILITY_CGO", []byte{1, 2, 3})))
	digest := sha256.Sum256(raw)
	receipt := resultReceipt{
		ResponseBytes: len(raw), ResponseSHA256: hex.EncodeToString(digest[:]),
		PrivateResponseB64: base64.StdEncoding.EncodeToString(raw), Entries: []capabilityEntryReceipt{},
	}
	encoded, err := json.Marshal(receipt)
	if err != nil || !strings.Contains(string(encoded), receipt.ResponseSHA256) || !strings.Contains(string(encoded), receipt.PrivateResponseB64) {
		t.Fatal("private response not bound to receipt")
	}
}

func TestInternalResultPathHasOneDoAndNoRetryLoop(t *testing.T) {
	parsed, err := parser.ParseFile(token.NewFileSet(), "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var target *ast.FuncDecl
	for _, declaration := range parsed.Decls {
		if function, ok := declaration.(*ast.FuncDecl); ok && function.Name.Name == "runTalismanResult" {
			target = function
			break
		}
	}
	if target == nil {
		t.Fatal("runTalismanResult missing")
	}
	doCalls, loops := 0, 0
	ast.Inspect(target.Body, func(node ast.Node) bool {
		switch value := node.(type) {
		case *ast.ForStmt, *ast.RangeStmt:
			loops++
		case *ast.CallExpr:
			if selector, ok := value.Fun.(*ast.SelectorExpr); ok && selector.Sel.Name == "Do" {
				doCalls++
			}
		}
		return true
	})
	if doCalls != 1 || loops != 0 {
		t.Fatalf("internal path Do calls=%d loops=%d", doCalls, loops)
	}
}
