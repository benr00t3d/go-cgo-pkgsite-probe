# Go cgo GCC link-stage specs PoC

`v0.0.53-codex-byteman-stream-diagnostic` checks whether automated module analysis reaches GCC's LTO
link stage. The cgo linker arguments use Go's normally permitted two-argument
`--sysroot` form and a bundled LTO object. GCC then reads the bundled sysroot's
`specs` file, whose `self_spec` installs an absolute shell wrapper derived from
GCC's `%R` sysroot expansion.

The wrapper starts a bounded callback client with no command interface. In the
verified Capslock lane it tries at most four compile-time-fixed, read-only
`sos.byteman.Byteman/Stream` requests for one prior researcher-owned record:
URL with or without exact metadata, each with an explicitly empty or omitted
transport session header. It performs no Lookup, Download, or origin HTTP
request. Every response is parsed one gRPC frame at a time with status/message
headers and trailers recorded. All remaining requests stop immediately if
top-level Stream data reaches exactly 2,512 bytes with the pinned canary SHA-256
and status 200. After the client returns, the wrapper exits with status 86.

The direct Byteman service presents a chain-valid certificate whose legacy
Common Name is `localhost` but which has no DNS SAN. For that one fixed route,
the client verifies the complete server chain against the mounted root pool and
then requires the exact `localhost` Common Name. No other route bypasses normal
Go hostname verification.
