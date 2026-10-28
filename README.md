# v0.0.126 Talisman Result receipt (prepared, disabled)

This immutable probe is prepared to make one read-only
`sos.talisman.Talisman/Result` request from the production Capslock lane for
the researcher-owned analysis record:

`github.com/benr00t3d/go-cgo-pkgsite-probe@v0.0.121-codex`

The exact request is a 65-byte unary gRPC body, independently decoded and
pinned by length and SHA-256. The client sends a preflight receipt before the
request and never retries. It accepts only one complete response frame,
HTTP/gRPC success with one status-zero trailer, and an exact production
`CapabilityResultResponse` containing a non-empty `map<string, bytes>`.

The disclosure receipt contains capability keys plus each value's byte length
and SHA-256. The complete owned response is bound into the result report but
is retained only in a private Cloud Logging receipt. After a live run that raw
receipt must be exported mode 600, excluded from disclosure manifests, and
the receiver deleted. The redacted result log never contains the raw response.

The checked-in client is intentionally disabled: its callback URL, session,
and URL digest are empty. Nothing in this branch has been published, tagged,
deployed, or submitted for analysis.
