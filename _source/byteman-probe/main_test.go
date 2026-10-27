package main

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func response(status int, headers http.Header, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     headers,
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func TestFixedTargetsAndPermissions(t *testing.T) {
	wantBuckets := [...]string{"sos-byteman-downloads-oregon", "sos-byteman-temp-oregon"}
	wantPermissions := [...]string{
		"storage.objects.get", "storage.objects.create", "storage.objects.delete",
		"storage.objects.list", "storage.buckets.get", "storage.buckets.update",
	}
	if fixedBuckets != wantBuckets || fixedPermissions != wantPermissions {
		t.Fatalf("fixed IAM scope changed: buckets=%q permissions=%q", fixedBuckets, fixedPermissions)
	}
}

func TestMetadataTokenRequestIsExactAndTokenIsNotInError(t *testing.T) {
	const secret = "unit-test-secret-token"
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet || request.URL.String() != metadataTokenURL ||
			request.Header.Get("Metadata-Flavor") != "Google" || request.Header.Get("Authorization") != "" ||
			request.Body != nil {
			t.Fatalf("metadata request was not exact: method=%q url=%q headers=%v", request.Method, request.URL, request.Header)
		}
		return response(http.StatusOK, http.Header{
			"Metadata-Flavor": []string{"Google"},
			"Content-Type":    []string{"application/json; charset=utf-8"},
		},
			`{"access_token":"`+secret+`","expires_in":300,"token_type":"Bearer"}`), nil
	})}
	token, err := fetchMetadataToken(client)
	if err != nil || token != secret {
		t.Fatalf("metadata token = %q, %v", token, err)
	}
	badClient := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response(http.StatusOK, http.Header{
			"Metadata-Flavor": []string{"Google"},
			"Content-Type":    []string{"application/json"},
		},
			`{"access_token":"`+secret+`","expires_in":0,"token_type":"Bearer"}`), nil
	})}
	_, err = fetchMetadataToken(badClient)
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("metadata error exposed token: %v", err)
	}
}

func TestTestIAMPermissionsRequestIsExactAndReadOnly(t *testing.T) {
	const token = "unit-test-token"
	wantGranted := []string{"storage.buckets.get", "storage.objects.get"}
	requests := 0
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		if request.Method != http.MethodGet || request.URL.Scheme != "https" ||
			request.URL.Host != storageAPIHost || request.URL.Path != "/storage/v1/b/"+fixedBuckets[0]+"/iam/testPermissions" ||
			request.Header.Get("Authorization") != "Bearer "+token || request.Body != nil {
			t.Fatalf("IAM request was not fixed/read-only: method=%q url=%q", request.Method, request.URL)
		}
		if got := request.URL.Query()["permissions"]; !reflect.DeepEqual(got, fixedPermissions[:]) {
			t.Fatalf("permissions query = %q, want %q", got, fixedPermissions)
		}
		return response(http.StatusOK, http.Header{"Content-Type": []string{"application/json"}},
			`{"permissions":["storage.objects.get","storage.buckets.get"]}`), nil
	})}
	result := testBucketPermissions(client, token, fixedBuckets[0])
	if requests != 1 || result.HTTPStatus != http.StatusOK || result.Error != "" || !reflect.DeepEqual(result.Granted, wantGranted) {
		t.Fatalf("IAM result = %#v, requests=%d", result, requests)
	}
}

func TestUnknownBucketIsRejectedBeforeRequest(t *testing.T) {
	requests := 0
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		requests++
		return nil, io.ErrUnexpectedEOF
	})}
	result := testBucketPermissions(client, "unit-test-token", "unapproved-bucket")
	if requests != 0 || result.Error == "" || result.HTTPStatus != 0 || len(result.Granted) != 0 {
		t.Fatalf("unknown bucket result = %#v, requests=%d", result, requests)
	}
}

func TestIAMResponseReportsOnlyBoundedStatusAndGrantedNames(t *testing.T) {
	const secretMessage = "sensitive provider detail"
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response(http.StatusForbidden, http.Header{"Content-Type": []string{"application/json"}},
			`{"error":{"status":"PERMISSION_DENIED","message":"`+secretMessage+`"}}`), nil
	})}
	result := testBucketPermissions(client, "unit-test-token", fixedBuckets[1])
	if result.HTTPStatus != http.StatusForbidden || result.APIStatus != "PERMISSION_DENIED" ||
		result.Error != "" || len(result.Granted) != 0 {
		t.Fatalf("error IAM result = %#v", result)
	}
	encoded := []byte(result.APIStatus + result.Error + strings.Join(result.Granted, ","))
	if bytes.Contains(encoded, []byte(secretMessage)) {
		t.Fatal("provider error message was exposed")
	}
}

func TestUnexpectedOrDuplicateGrantedPermissionIsRejected(t *testing.T) {
	for _, body := range []string{
		`{"permissions":["storage.objects.update"]}`,
		`{"permissions":["storage.objects.get","storage.objects.get"]}`,
	} {
		client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return response(http.StatusOK, http.Header{"Content-Type": []string{"application/json"}}, body), nil
		})}
		result := testBucketPermissions(client, "unit-test-token", fixedBuckets[0])
		if result.Error == "" || len(result.Granted) != 0 {
			t.Fatalf("unexpected response accepted: %#v", result)
		}
	}
}

func TestTokenAndJSONMediaTypeBounds(t *testing.T) {
	if !validAccessToken("ascii-token._~") || validAccessToken("contains space") ||
		validAccessToken("unicode-\u2603") || !isJSONContentType("Application/JSON; charset=UTF-8") ||
		isJSONContentType("text/json") {
		t.Fatal("token or JSON media-type bounds changed")
	}
}

func TestFixedIAMURLShape(t *testing.T) {
	for _, bucket := range fixedBuckets {
		raw, err := fixedTestPermissionsURL(bucket)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Scheme != "https" || parsed.Host != storageAPIHost ||
			parsed.Path != "/storage/v1/b/"+bucket+"/iam/testPermissions" || len(parsed.Query()) != 1 {
			t.Fatalf("fixed IAM URL = %q, %v", raw, err)
		}
	}
}

func TestCallbackConfigurationIsExact(t *testing.T) {
	priorGeneric, priorCompiler := genericResultURL, compilerResultURL
	priorSession, priorAgent := sessionNonce, probeUserAgent
	sessionNonce = strings.Repeat("a", 64)
	probeUserAgent = expectedUserAgent
	genericResultURL = "https://callback.example.invalid/v1/result/" + sessionNonce + "/generic"
	compilerResultURL = "https://callback.example.invalid/v1/result/" + sessionNonce + "/compiler"
	t.Cleanup(func() {
		genericResultURL, compilerResultURL = priorGeneric, priorCompiler
		sessionNonce, probeUserAgent = priorSession, priorAgent
	})
	if err := validateCallbackConfiguration(); err != nil {
		t.Fatal(err)
	}
	compilerResultURL = "https://other.example.invalid/v1/result/" + sessionNonce + "/compiler"
	if err := validateCallbackConfiguration(); err == nil {
		t.Fatal("split callback origins were accepted")
	}
}

func TestClassifyLaneUsesExactVersionedRoots(t *testing.T) {
	capslock := "/capslock/modcache/" + moduleName + "@" + probeVersion
	generic := "/var/tmp/gopath/pkg/mod/" + moduleName + "@" + probeVersion
	pid1 := "/talisman-worker-capabilities -http=:8080"
	if classifyLaneWithIdentity(capslock, 0, pid1) != "capslock" ||
		classifyLaneWithIdentity(capslock+"/x", 0, pid1) != "capslock" ||
		classifyLaneWithIdentity(generic, 1000, "/sbin/init") != "generic" ||
		classifyLaneWithIdentity("/capslock/modcache/other@v1", 0, pid1) != "unknown" {
		t.Fatal("lane classification accepted the wrong root")
	}
	if classifyLaneWithIdentity(capslock, 1000, pid1) == "capslock" ||
		classifyLaneWithIdentity(capslock, 0, "/sbin/init") == "capslock" {
		t.Fatal("Capslock lane accepted the wrong UID or PID 1 marker")
	}
}
