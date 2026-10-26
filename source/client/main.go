package main

import (
	"io"
	"net/http"
	"time"
)

// canaryURL is fixed at build time. The response is discarded and no response
// bytes are evaluated, executed, or used to select another destination.
var canaryURL string

func main() {
	client := &http.Client{Timeout: 5 * time.Second}
	response, err := client.Get(canaryURL)
	if err != nil {
		return
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
}
