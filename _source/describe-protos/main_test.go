package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateRuntimeConfiguration(t *testing.T) {
	callbackSession = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	callbackURL = "https://us-central1-s0victim-44547.cloudfunctions.net/go-cgo-v120-identity-codex/v1/session/" + callbackSession
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
	for _, id := range []string{"path_meta", "dir_meta", "write_canary", "pid1", "fixed_paths"} {
		if validRequestShape(requestSpec{ID: id, Args: map[string]string{}}, "") {
			t.Fatalf("legacy probe %s remained reachable", id)
		}
	}
	for _, id := range []string{"kubernetes_authz", "internal_grpc_identity"} {
		if !validRequestShape(requestSpec{ID: id, Args: map[string]string{}}, "") {
			t.Fatalf("%s request rejected", id)
		}
		if validRequestShape(requestSpec{ID: id, Args: map[string]string{"path": "/tmp"}}, "") {
			t.Fatalf("%s accepted arguments", id)
		}
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
	matches, err := filepath.Glob(filepath.Join(directory, ".go-cgo-v120-*"))
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

func TestSafeJWTClaimsReturnsOnlyAllowlistedClaims(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","secret_header":"do-not-return"}`))
	payloadValue := map[string]any{
		"sub":     "system:serviceaccount:default:talisman-worker",
		"iss":     "https://kubernetes.default.svc.cluster.local",
		"aud":     []string{"https://kubernetes.default.svc"},
		"exp":     1999999999,
		"private": "do-not-return",
		"kubernetes.io": map[string]any{
			"namespace": "default",
			"pod":       map[string]string{"name": "worker-abc", "uid": "01234567-89ab-cdef-0123-456789abcdef"},
			"node":      map[string]string{"name": "do-not-return"},
		},
	}
	payload, err := json.Marshal(payloadValue)
	if err != nil {
		t.Fatal(err)
	}
	token := header + "." + base64.RawURLEncoding.EncodeToString(payload) + ".secret-signature"
	claims := safeJWTClaims([]byte(token))
	encoded, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	for _, forbidden := range []string{"do-not-return", "secret-signature", header, token} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("JWT output leaked %q: %s", forbidden, text)
		}
	}
	if claims["sub"] == nil || claims["pod"] == nil || claims["namespace"] != "default" {
		t.Fatalf("missing allowlisted claims: %#v", claims)
	}
}

func TestKubernetesChecksUseOnlyVersionAndSSAR(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("unexpected authorization header")
		}
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/version":
			_, _ = io.WriteString(response, `{"major":"1","minor":"30","platform":"linux/amd64"}`)
		case "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews":
			var review selfSubjectAccessReview
			if !decodeOneJSON(mustReadTest(t, request.Body), &review) {
				t.Error("invalid review request")
			}
			review.Status.Allowed = review.Spec.ResourceAttributes.Resource == "jobs"
			review.Status.Denied = !review.Status.Allowed
			review.Status.Reason = "reason-must-not-be-returned"
			response.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(response).Encode(review)
		default:
			t.Errorf("unexpected path %s", request.URL.Path)
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	result := kubernetesResult{Checks: []kubePermissionResult{}}
	executeKubernetesChecks(server.Client(), server.URL, "test-token", "default", &result)
	if !result.APIVersionReachable || result.Major != "1" || len(result.Checks) != len(kubePermissions) {
		t.Fatalf("unexpected result: %#v", result)
	}
	for _, check := range result.Checks {
		if !check.ValidResponse {
			t.Fatalf("invalid SSAR result: %#v", check)
		}
	}
	encoded, _ := json.Marshal(result)
	if strings.Contains(string(encoded), "reason-must-not-be-returned") {
		t.Fatalf("raw authorization reason leaked: %s", encoded)
	}
}

func TestReflectionParserKeepsOnlyFixedServiceNames(t *testing.T) {
	service := append([]byte{0x0a, byte(len("sos.queue.Queue"))}, []byte("sos.queue.Queue")...)
	list := append([]byte{0x0a, byte(len(service))}, service...)
	frame := append([]byte{0x32, byte(len(list))}, list...)
	found := reflectedServiceNames([][]byte{frame})
	if !found["sos.queue.Queue"] || found["not.fixed.Service"] {
		t.Fatalf("unexpected reflected services: %#v", found)
	}
}

func TestParseGRPCFramesRejectsCompressedAndTruncated(t *testing.T) {
	valid := []byte{0, 0, 0, 0, 2, 8, 1}
	frames, bytesRead, err := parseGRPCFrames(valid, 2)
	if err != nil || len(frames) != 1 || bytesRead != 2 {
		t.Fatalf("valid frame rejected: %v %d %v", frames, bytesRead, err)
	}
	for _, invalid := range [][]byte{{1, 0, 0, 0, 0}, {0, 0, 0, 0, 2, 8}} {
		if _, _, err := parseGRPCFrames(invalid, 2); err == nil {
			t.Fatalf("invalid frame accepted: %x", invalid)
		}
	}
}

func mustReadTest(t *testing.T, reader io.Reader) []byte {
	t.Helper()
	value, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func strconvForTest(value int) string {
	const digits = "0123456789"
	if value < 10 {
		return string(digits[value])
	}
	return string(digits[value/10]) + string(digits[value%10])
}
