package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateRuntimeConfiguration(t *testing.T) {
	callbackSession = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	callbackURL = "https://us-central1-s0victim-44547.cloudfunctions.net/go-cgo-v122-recovery-codex/v1/session/" + callbackSession
	digest := sha256.Sum256([]byte(callbackURL))
	callbackURLSHA256 = hex.EncodeToString(digest[:])
	if err := validateRuntimeConfiguration(); err != nil {
		t.Fatal(err)
	}
}

func TestValidatePathArgument(t *testing.T) {
	for _, path := range []string{"/", "/tmp", "/proc/self/status", expectedOrigin} {
		if err := validatePathArgument(path); err != nil {
			t.Errorf("allowed path %q: %v", path, err)
		}
	}
	denied := []string{
		"", "relative", "/tmp/../etc", "/tmp//x", "/tmp/\x00x",
		"/proc/self/fd/1", "/proc/1/mem", "/proc/1/map_files/1-2", "/proc/kcore",
		"/" + strings.Repeat("a", maximumPath+1),
	}
	for _, path := range denied {
		if err := validatePathArgument(path); err == nil {
			t.Errorf("denied path accepted: %q", path)
		}
	}
}

func TestValidateDirectoryArgument(t *testing.T) {
	for _, path := range []string{"/capslock", "/tmp/example", "/proc/self", "/proc/1/rootfs", "/usr/local/go", "/app", "/bundle"} {
		if err := validateDirectoryArgument(path); err != nil {
			t.Errorf("allowed directory %q: %v", path, err)
		}
	}
	for _, path := range []string{"/etc", "/etc/tls", "/etc/tls/client", "/proc/2", "/workspace"} {
		if err := validateDirectoryArgument(path); err == nil {
			t.Errorf("denied directory accepted: %q", path)
		}
	}
}

func TestRequestShape(t *testing.T) {
	if !validRequestShape(requestSpec{ID: "identity", Args: map[string]string{}}, "") {
		t.Fatal("identity request rejected")
	}
	if validRequestShape(requestSpec{ID: "identity", Args: map[string]string{"path": "/tmp"}}, "") {
		t.Fatal("identity arguments accepted")
	}
	if !validRequestShape(requestSpec{ID: "path_meta", Args: map[string]string{"path": "/tmp"}}, "") {
		t.Fatal("path_meta rejected")
	}
	if validRequestShape(requestSpec{ID: "dir_meta", Args: map[string]string{"path": "/etc/tls/client"}}, "") {
		t.Fatal("TLS listing accepted")
	}
	if validRequestShape(requestSpec{ID: "write_canary", Args: map[string]string{"path": "/etc"}}, "/tmp/work") {
		t.Fatal("out-of-scope canary accepted")
	}
	if !validRequestShape(requestSpec{ID: "process_meta", Args: map[string]string{"pid": "1"}}, "") {
		t.Fatal("process_meta rejected")
	}
	for _, pid := range []string{"", "0", "01", "-1", "4194305", "self"} {
		if validRequestShape(requestSpec{ID: "process_meta", Args: map[string]string{"pid": pid}}, "") {
			t.Fatalf("process_meta accepted pid %q", pid)
		}
	}
	if validRequestShape(requestSpec{ID: "protobuf_services", Args: map[string]string{"path": "/proc/1/exe"}}, "") {
		t.Fatal("fixed protobuf probe accepted caller path")
	}
}

func TestTranscriptBindsRequestAndResult(t *testing.T) {
	previous := initialTranscript(strings.Repeat("a", 64))
	request := requestSpec{ID: "path_meta", Args: map[string]string{"path": "/tmp"}}
	first, err := stepTranscript(previous, 1, request, "ok", "", map[string]any{"exists": true})
	if err != nil {
		t.Fatal(err)
	}
	second, err := stepTranscript(previous, 1, request, "ok", "", map[string]any{"exists": true})
	if err != nil || first != second {
		t.Fatalf("transcript not deterministic: %q %q %v", first, second, err)
	}
	changed, _ := stepTranscript(previous, 1, request, "error", "path_meta_failed", nil)
	if changed == first {
		t.Fatal("status/error not bound into transcript")
	}
}

func TestPathMetadataDoesNotFollowFinalSymlink(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	link := filepath.Join(directory, "link")
	if err := os.WriteFile(target, []byte("content-not-read"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	value, err := collectPathMetadata(link)
	if err != nil {
		t.Fatal(err)
	}
	if value.Kind != "symlink" || value.SymlinkTarget != target || value.Size == int64(len("content-not-read")) {
		t.Fatalf("unexpected symlink metadata: %+v", value)
	}
}

func TestDirectoryMetadataIsBounded(t *testing.T) {
	directory := t.TempDir()
	for index := 0; index < 66; index++ {
		name := filepath.Join(directory, "entry-"+strconvForTest(index))
		if err := os.WriteFile(name, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	value, err := collectDirectoryMetadata(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(value.Entries) != 64 || !value.Truncated {
		t.Fatalf("entries=%d truncated=%t", len(value.Entries), value.Truncated)
	}
}

func TestWriteCanaryIsScopedAndCleaned(t *testing.T) {
	callbackSession = strings.Repeat("b", 64)
	directory := t.TempDir()
	state := &clientState{workspace: directory}
	value, err := runWriteCanary(directory, state, 3)
	if err != nil {
		t.Fatal(err)
	}
	if value["cleanup_confirmed"] != true || value["unlinked"] != true {
		t.Fatalf("canary not cleaned: %+v", value)
	}
	matches, err := filepath.Glob(filepath.Join(directory, ".go-cgo-v122-*"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("canary remnants: %v %v", matches, err)
	}
	if _, err := runWriteCanary("/etc", state, 4); err == nil {
		t.Fatal("out-of-scope canary ran")
	}
}

func TestProbeFailureReturnsEnvelopeError(t *testing.T) {
	value, status, errorText := executeProbe(requestSpec{ID: "dir_meta", Args: map[string]string{"path": "/etc/tls/client"}}, &clientState{}, 1)
	if value != nil || status != "error" || errorText != "request_denied" {
		t.Fatalf("failure result = %#v %q %q", value, status, errorText)
	}
}

func TestSanitizeText(t *testing.T) {
	if got := sanitizeText("ok\nnot", 64); got != "ok_not" {
		t.Fatalf("sanitizeText = %q", got)
	}
}

func TestProtocolPendingShape(t *testing.T) {
	fingerprint, transcript := strings.Repeat("a", 64), strings.Repeat("b", 64)
	value := protocolResponse{
		Fingerprint: fingerprint, Sequence: 7, TimestampUnix: 1, Status: "ok",
		Transcript: transcript, Request: requestSpec{Args: map[string]string{}}, Pending: true, PollAfterMS: 1000,
	}
	if !validProtocolReply(value, fingerprint, transcript, 7) {
		t.Fatal("valid pending reply rejected")
	}
	value.Request.ID = "path_meta"
	if validProtocolReply(value, fingerprint, transcript, 7) {
		t.Fatal("pending reply with request accepted")
	}
}

func TestCollectSecurityStatusIsMetadataOnly(t *testing.T) {
	value, err := collectSecurityStatus()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"self", "pid1"} {
		item := value[name]
		if len(item.UID) != 4 || len(item.GID) != 4 || !validCapabilityMask(item.CapEffective) {
			t.Fatalf("%s security metadata incomplete: %+v", name, item)
		}
	}
}

func TestInventoryReturnsNamesAndMetadataOnly(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "token-name")
	if err := os.WriteFile(path, []byte("content-must-not-appear"), 0o600); err != nil {
		t.Fatal(err)
	}
	value := collectInventory([]string{directory})
	if len(value) != 1 || len(value[0].Entries) != 1 || value[0].Entries[0].Name != "token-name" {
		t.Fatalf("unexpected inventory: %+v", value)
	}
	encoded := string(mustCanonicalForTest(t, value))
	if strings.Contains(encoded, "content-must-not-appear") {
		t.Fatal("inventory included file content")
	}
}

func TestSensitiveArgumentRedactionPredicate(t *testing.T) {
	for _, value := range []string{"--token=abc", "-password=abc", "--client-secret=x"} {
		if !sensitiveArgument(value) {
			t.Fatalf("sensitive argument not detected: %q", value)
		}
	}
	for _, value := range []string{"-talisman_addr=service:9000", "-tls_key=/etc/tls/client/tls.key"} {
		if sensitiveArgument(value) {
			t.Fatalf("metadata-only argument over-redacted: %q", value)
		}
	}
}

func appendProtoField(destination []byte, number int, value []byte) []byte {
	destination = binary.AppendUvarint(destination, uint64(number<<3|2))
	destination = binary.AppendUvarint(destination, uint64(len(value)))
	return append(destination, value...)
}

func syntheticDescriptor(packageName, serviceName string, methods ...string) []byte {
	service := appendProtoField(nil, 1, []byte(serviceName))
	for _, name := range methods {
		method := appendProtoField(nil, 1, []byte(name))
		method = appendProtoField(method, 2, []byte(".example.Input"))
		method = appendProtoField(method, 3, []byte(".example.Output"))
		service = appendProtoField(service, 2, method)
	}
	file := appendProtoField(nil, 1, []byte("test.proto"))
	file = appendProtoField(file, 2, []byte(packageName))
	file = appendProtoField(file, 6, service)
	return appendProtoField(file, 12, []byte("proto3"))
}

func TestDescriptorExtractionReturnsOnlyAllowedNames(t *testing.T) {
	allowed := servicesFromDescriptor(syntheticDescriptor("sos.queue", "Queue", "Push", "Health"))
	if len(allowed) != 1 || allowed[0].Name != "sos.queue.Queue" || strings.Join(allowed[0].Methods, ",") != "Health,Push" {
		t.Fatalf("unexpected allowed descriptor: %+v", allowed)
	}
	if denied := servicesFromDescriptor(syntheticDescriptor("other.internal", "Admin", "Delete")); len(denied) != 0 {
		t.Fatalf("unrelated descriptor escaped filter: %+v", denied)
	}
}

func mustCanonicalForTest(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := canonicalJSON(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func strconvForTest(value int) string {
	const digits = "0123456789"
	if value < 10 {
		return string(digits[value])
	}
	return string(digits[value/10]) + string(digits[value%10])
}
