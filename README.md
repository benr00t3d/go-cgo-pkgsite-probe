# Go cgo GCC link-stage specs PoC

`v0.0.52-codex-byteman-stream-readback` checks whether automated module analysis reaches GCC's LTO
link stage. The cgo linker arguments use Go's normally permitted two-argument
`--sysroot` form and a bundled LTO object. GCC then reads the bundled sysroot's
`specs` file, whose `self_spec` installs an absolute shell wrapper derived from
GCC's `%R` sysroot expansion.

The wrapper starts a bounded callback client with no command interface. In the
verified Capslock lane it makes one read-only `sos.byteman.Byteman/Stream` call
for a compile-time-fixed, researcher-owned Go module URL and exact metadata.
It performs no Lookup, Download, or origin HTTP request. The response is read
one gRPC frame at a time and accepted only if top-level Stream data reaches
exactly 2,512 bytes with the pinned canary SHA-256; the client closes the stream
immediately at that point rather than waiting for server EOF. After the client
returns, the wrapper exits with status 86 so execution remains observable.

The direct Byteman service presents a chain-valid certificate whose legacy
Common Name is `localhost` but which has no DNS SAN. For that one fixed route,
the client verifies the complete server chain against the mounted root pool and
then requires the exact `localhost` Common Name. No other route bypasses normal
Go hostname verification.
