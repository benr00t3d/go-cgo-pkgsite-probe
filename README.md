# Go cgo GCC link-stage specs PoC

`v0.0.56-codex-byteman-persisted-record-lookup` checks whether automated module analysis reaches GCC's LTO
link stage. The cgo linker arguments use Go's normally permitted two-argument
`--sysroot` form and a bundled LTO object. GCC then reads the bundled sysroot's
`specs` file, whose `self_spec` installs an absolute shell wrapper derived from
GCC's `%R` sysroot expansion.

The wrapper starts a bounded callback client with no command or plan interface.
In the verified Capslock lane its only business operation is the read-only
`sos.byteman.Byteman/Lookup` RPC on the direct `byteman` service. The request is
one source-pinned URL field naming the previously fetched v44 canary for the
separate researcher-owned module
`github.com/benr00t3d/go-byteman-crosswrite-canary@v0.0.1`.

The server-streaming response is read frame by frame and closed immediately
after one exact persisted Download record is found. The source pins the full
record, digest-message, metadata, path, and service-ID fingerprints. It also
requires size 2,512, status 200, and raw SHA-512, SHA-256, SHA-1, and MD5 values
recomputed from the inert canary ZIP. Compressed, oversized, malformed,
unknown, duplicate, or excess records fail closed. Header and trailer gRPC
status/message values and frame hashes are recorded. The client makes no
Stream, Download, origin, metadata-token, cloud API, or dynamic command
request. RPCs carry the fixed empty `X-SOS-SessionID` metadata used by the
production client. After the client returns, the wrapper exits with status 86
so execution remains observable.

The direct Byteman service presents a chain-valid certificate whose legacy
Common Name is `localhost` but which has no DNS SAN. For that one fixed route,
the client verifies the complete server chain against the mounted root pool and
then requires the exact `localhost` Common Name. No other route bypasses normal
Go hostname verification.
