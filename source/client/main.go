package main

import (
	"io"
	"net/http"
	"time"
)

const canaryURL = "https://go-cgo-pkgsite-canary-1026-o324i7mbdq-uc.a.run.app/pkgsite-remote-20261026-a5"

func main() {
	client := &http.Client{Timeout: 5 * time.Second}
	response, err := client.Get(canaryURL)
	if err != nil {
		return
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
}
