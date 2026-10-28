package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestObserveFixedFileClassifiesExactOtherAndMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "marker.go")
	body := []byte("synthetic owned marker fixture\n")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(body)
	want := hex.EncodeToString(digest[:])
	if got := observeFixedFile(path, int64(len(body)), want); got.State != "exact" || got.Bytes != int64(len(body)) || got.SHA256 != want {
		t.Fatalf("exact observation = %#v", got)
	}
	if got := observeFixedFile(path, int64(len(body)), strings.Repeat("0", 64)); got.State != "other" || got.SHA256 != want {
		t.Fatalf("other observation = %#v", got)
	}
	if got := observeFixedFile(path+".missing", 1, strings.Repeat("0", 64)); got.State != "missing" || got.Bytes != 0 || got.SHA256 != "" {
		t.Fatalf("missing observation = %#v", got)
	}
}

func TestObserveFixedFileDoesNotFollowSymlink(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	link := filepath.Join(directory, "link")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if got := observeFixedFile(link, 1, strings.Repeat("0", 64)); got.State != "other" || got.SHA256 != "" {
		t.Fatalf("symlink observation = %#v", got)
	}
}

func TestRuntimeConfigurationIsExact(t *testing.T) {
	priorURL, priorSession, priorDigest := callbackURL, callbackSession, callbackURLSHA256
	t.Cleanup(func() { callbackURL, callbackSession, callbackURLSHA256 = priorURL, priorSession, priorDigest })
	callbackSession = strings.Repeat("a", 64)
	callbackURL = "https://owned.example.invalid/go-cgo-modcache-proof-a102/v1/cache-a110/" + callbackSession
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
