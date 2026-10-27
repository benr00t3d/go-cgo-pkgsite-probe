package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyExactMarkerUsesOnlySizeAndDigest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "marker.go")
	body := []byte("synthetic owned marker fixture\n")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(body)
	want := hex.EncodeToString(digest[:])
	if err := verifyExactMarker(path, int64(len(body)), want); err != nil {
		t.Fatal(err)
	}
	if err := verifyExactMarker(path, int64(len(body)), strings.Repeat("0", 64)); err == nil {
		t.Fatal("changed digest was accepted")
	}
}

func TestVerifyExactMarkerRejectsSymlink(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	link := filepath.Join(directory, "link")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := verifyExactMarker(link, 1, strings.Repeat("0", 64)); err == nil {
		t.Fatal("symlink was accepted")
	}
}

func TestRuntimeConfigurationIsExact(t *testing.T) {
	priorURL, priorSession, priorDigest := callbackURL, callbackSession, callbackURLSHA256
	t.Cleanup(func() { callbackURL, callbackSession, callbackURLSHA256 = priorURL, priorSession, priorDigest })
	callbackSession = strings.Repeat("a", 64)
	callbackURL = "https://owned.example.invalid/v1/consumer-a101/" + callbackSession
	digest := sha256.Sum256([]byte(callbackURL))
	callbackURLSHA256 = hex.EncodeToString(digest[:])
	if err := validateRuntimeConfiguration(); err != nil {
		t.Fatal(err)
	}
	callbackURL += "?unexpected=1"
	if err := validateRuntimeConfiguration(); err == nil {
		t.Fatal("query-bearing callback URL was accepted")
	}
}
