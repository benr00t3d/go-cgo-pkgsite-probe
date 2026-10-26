package main

import (
	"crypto/subtle"
	"io"
	"net/http"
	"time"
)

// These values are fixed at build time. The response is compared with one
// fixed receipt and is never evaluated, executed, or used to select a target.
var challengeURL string
var acknowledgementURL string
var expectedReceipt string
var probeUserAgent string

const maximumReceiptBytes = 4096

func main() {
	if challengeURL == "" || acknowledgementURL == "" || probeUserAgent == "" ||
		len(expectedReceipt) == 0 || len(expectedReceipt) > maximumReceiptBytes {
		return
	}
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	challenge, err := http.NewRequest(http.MethodGet, challengeURL, nil)
	if err != nil {
		return
	}
	challenge.Header.Set("User-Agent", probeUserAgent)
	challenge.Header.Set("Accept", "text/plain")
	response, err := client.Do(challenge)
	if err != nil {
		return
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, maximumReceiptBytes+1))
	_ = response.Body.Close()
	if readErr != nil || response.StatusCode != http.StatusOK ||
		len(body) != len(expectedReceipt) ||
		subtle.ConstantTimeCompare(body, []byte(expectedReceipt)) != 1 {
		return
	}

	acknowledgement, err := http.NewRequest(http.MethodGet, acknowledgementURL, nil)
	if err != nil {
		return
	}
	acknowledgement.Header.Set("User-Agent", probeUserAgent)
	acknowledgement.Header.Set("Accept", "text/plain")
	ackResponse, err := client.Do(acknowledgement)
	if err != nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(ackResponse.Body, maximumReceiptBytes))
	_ = ackResponse.Body.Close()
}
