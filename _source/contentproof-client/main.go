// Command contentproof-client performs one fixed, bounded observation of the
// owned B marker and submits one non-sensitive receipt. It has no command,
// environment, credential, process, internal-RPC, or arbitrary-path surface.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

var callbackURL string
var callbackSession string
var callbackURLSHA256 string

const (
	consumerModule       = "github.com/benr00t3d/go-cgo-pkgsite-probe"
	consumerVersion      = "v0.0.101-codex"
	targetModule         = "github.com/benr00t3d/go-byteman-crosswrite-canary"
	targetVersion        = "v0.0.2"
	expectedOriginDir    = "/capslock/modcache/github.com/benr00t3d/go-cgo-pkgsite-probe@v0.0.101-codex"
	markerPath           = "/capslock/modcache/github.com/benr00t3d/go-byteman-crosswrite-canary@v0.0.2/byteman_crosswrite_marker.go"
	targetArchiveSHA256  = "e7c6ef7862d1fe3c34b3a45a5bf550dba42be42fd8d73c5404886c2dc3c24ee3"
	targetModuleH1       = "h1:W0kHBdISCu34dXFrjBSGXAZ+/4qd/O6mWelMz0v0UYg="
	markerFileSHA256     = "d98d03a4cfe731a31dafa1a90af3cd7374dae985c79425a052e3b9fe42f39179"
	markerFileBytes      = int64(250)
	expectedUserAgent    = "go-cgo-pkgsite-probe-v101-content-consumer"
	callbackTimeout      = 30 * time.Second
	maximumResponseBytes = 1024
)

type receipt struct {
	Schema              string `json:"schema"`
	ConsumerModule      string `json:"consumer_module"`
	ConsumerVersion     string `json:"consumer_version"`
	TargetModule        string `json:"target_module"`
	TargetVersion       string `json:"target_version"`
	TargetArchiveSHA256 string `json:"target_archive_sha256"`
	TargetModuleH1      string `json:"target_module_h1"`
	MarkerFileBytes     int64  `json:"marker_file_bytes"`
	MarkerFileSHA256    string `json:"marker_file_sha256"`
	Verified            bool   `json:"verified"`
}

func main() {
	if validateRuntimeConfiguration() != nil || len(os.Args) != 4 || os.Args[1] != "--specwrap" || os.Args[2] != "--origin-dir" {
		return
	}
	origin := filepath.Clean(os.Args[3])
	// Any non-Capslock/generic build stops before reading B or making a request.
	if origin != expectedOriginDir || os.Args[3] != origin {
		return
	}
	if verifyExactMarker(markerPath, markerFileBytes, markerFileSHA256) != nil {
		return
	}
	body, err := json.Marshal(receipt{
		Schema: "owned-go-content-consumer/v1", ConsumerModule: consumerModule,
		ConsumerVersion: consumerVersion, TargetModule: targetModule,
		TargetVersion: targetVersion, TargetArchiveSHA256: targetArchiveSHA256,
		TargetModuleH1: targetModuleH1, MarkerFileBytes: markerFileBytes,
		MarkerFileSHA256: markerFileSHA256, Verified: true,
	})
	if err != nil {
		return
	}
	_ = submitReceipt(body)
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

func validateRuntimeConfiguration() error {
	if !validNonce(callbackSession) || len(callbackURLSHA256) != 64 {
		return errors.New("invalid fixed callback identity")
	}
	parsed, err := url.Parse(callbackURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Hostname() == "" ||
		parsed.User != nil || parsed.Opaque != "" || parsed.RawPath != "" || parsed.RawQuery != "" ||
		parsed.ForceQuery || parsed.Fragment != "" || parsed.Path != "/v1/consumer-a101/"+callbackSession {
		return errors.New("invalid fixed callback URL")
	}
	digest := sha256.Sum256([]byte(callbackURL))
	if hex.EncodeToString(digest[:]) != callbackURLSHA256 {
		return errors.New("fixed callback digest mismatch")
	}
	return nil
}

func verifyExactMarker(path string, expectedBytes int64, expectedSHA256 string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || expectedBytes < 1 || expectedBytes > 4096 || len(expectedSHA256) != 64 {
		return errors.New("invalid fixed marker expectation")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return errors.New("fixed marker unavailable")
	}
	if !info.Mode().IsRegular() || info.Size() != expectedBytes {
		return errors.New("fixed marker type or size mismatch")
	}
	file, err := os.Open(path)
	if err != nil {
		return errors.New("fixed marker unavailable")
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, expectedBytes+1))
	if err != nil || int64(len(body)) != expectedBytes {
		return errors.New("fixed marker read mismatch")
	}
	digest := sha256.Sum256(body)
	if hex.EncodeToString(digest[:]) != expectedSHA256 {
		return errors.New("fixed marker digest mismatch")
	}
	return nil
}

func submitReceipt(body []byte) error {
	if len(body) < 1 || len(body) > 4096 {
		return errors.New("receipt size")
	}
	ctx, cancel := context.WithTimeout(context.Background(), callbackTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, callbackURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", expectedUserAgent)
	request.Header.Set("X-Codex-Probe-Session", callbackSession)
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: -1}
	transport := &http.Transport{
		Proxy: nil, DialContext: dialer.DialContext, ForceAttemptHTTP2: true,
		DisableKeepAlives: true, TLSHandshakeTimeout: 10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport, Timeout: callbackTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	responseBody, readErr := io.ReadAll(io.LimitReader(response.Body, maximumResponseBytes+1))
	if readErr != nil || len(responseBody) > maximumResponseBytes || response.StatusCode != http.StatusCreated {
		return errors.New("receipt callback rejected")
	}
	return nil
}
