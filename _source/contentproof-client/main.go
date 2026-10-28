// Command contentproof-client runs only after this independent worker has
// compiled owned B with the symbol injected by A111.
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
	consumerModule          = "github.com/benr00t3d/go-cgo-pkgsite-probe"
	consumerVersion         = "v0.0.112-codex"
	targetModule            = "github.com/benr00t3d/go-byteman-crosswrite-canary"
	targetVersion           = "v0.0.7"
	expectedOriginDir       = "/capslock/modcache/github.com/benr00t3d/go-cgo-pkgsite-probe@v0.0.112-codex"
	targetDir               = "/capslock/modcache/github.com/benr00t3d/go-byteman-crosswrite-canary@v0.0.7"
	canonicalCanaryPath     = targetDir + "/canary.go"
	canonicalCanarySHA256   = "6b1f0a01b3fc13dbb14ab80add947248e1b8f98429eb5877d23bd7a1c905aa6e"
	canonicalCanaryBytes    = int64(303)
	markerPath              = targetDir + "/a111_injected_content.go"
	markerSHA256            = "c836e79c4615e620b9ac5df957b74dcbbb6a7482a81e2c9b9ac4cf413131c8b1"
	markerBytes             = int64(158)
	consumerGate            = "reached_link_after_compiling_injected_b_symbol"
	expectedUserAgent       = "go-cgo-pkgsite-probe-v112-content-reader"
	callbackTimeout         = 30 * time.Second
	maximumObservedFileSize = int64(4096)
	maximumResponseBytes    = 1024
)

type fileObservation struct {
	State  string `json:"state"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

type receipt struct {
	Schema               string          `json:"schema"`
	ConsumerModule       string          `json:"consumer_module"`
	ConsumerVersion      string          `json:"consumer_version"`
	TargetModule         string          `json:"target_module"`
	TargetVersion        string          `json:"target_version"`
	ConsumerGate         string          `json:"consumer_gate"`
	MarkerFilename       string          `json:"marker_filename"`
	TargetDirPresent     bool            `json:"target_dir_present"`
	Before               fileObservation `json:"before"`
	After                fileObservation `json:"after"`
	WriteAttempted       bool            `json:"write_attempted"`
	MarkerPresent        bool            `json:"marker_present"`
	ExpectedMarkerSHA256 string          `json:"expected_marker_sha256"`
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
	directoryPresent := false
	if info, err := os.Lstat(targetDir); err == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
		directoryPresent = true
	}
	before := observeFixedFile(markerPath, markerBytes, markerSHA256)
	after := observeFixedFile(markerPath, markerBytes, markerSHA256)
	writeAttempted := false
	body, err := json.Marshal(receipt{
		Schema: "owned-live-content-consumption/v1", ConsumerModule: consumerModule,
		ConsumerVersion: consumerVersion, TargetModule: targetModule,
		TargetVersion: targetVersion, ConsumerGate: consumerGate,
		MarkerFilename: "a111_injected_content.go", TargetDirPresent: directoryPresent,
		Before: before, After: after, WriteAttempted: writeAttempted,
		MarkerPresent:        after.State == "exact",
		ExpectedMarkerSHA256: markerSHA256,
	})
	if err != nil {
		return
	}
	_ = submitReceipt(body)
}

func observeFixedFile(path string, expectedBytes int64, expectedSHA256 string) fileObservation {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || expectedBytes < 1 || expectedBytes > maximumObservedFileSize || len(expectedSHA256) != 64 {
		return fileObservation{State: "error"}
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return fileObservation{State: "missing"}
	}
	if err != nil {
		return fileObservation{State: "error"}
	}
	observation := fileObservation{State: "other", Bytes: info.Size()}
	if !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > maximumObservedFileSize {
		return observation
	}
	file, err := os.Open(path)
	if err != nil {
		return fileObservation{State: "error"}
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, maximumObservedFileSize+1))
	if err != nil || int64(len(body)) != info.Size() {
		return fileObservation{State: "error"}
	}
	digest := sha256.Sum256(body)
	observation.SHA256 = hex.EncodeToString(digest[:])
	if observation.Bytes == expectedBytes && observation.SHA256 == expectedSHA256 {
		observation.State = "exact"
	}
	return observation
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
		parsed.ForceQuery || parsed.Fragment != "" || parsed.Path != "/v1/result/"+callbackSession+"/reader" {
		return errors.New("invalid fixed callback URL")
	}
	digest := sha256.Sum256([]byte(callbackURL))
	if hex.EncodeToString(digest[:]) != callbackURLSHA256 {
		return errors.New("fixed callback digest mismatch")
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
