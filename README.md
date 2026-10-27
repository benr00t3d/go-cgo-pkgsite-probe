# Go cgo GCC link-stage specs PoC

`v0.0.50-codex-byteman-package-canary` checks whether automated module analysis reaches GCC's LTO
link stage. The cgo linker arguments use Go's normally permitted two-argument
`--sysroot` form and a bundled LTO object. GCC then reads the bundled sysroot's
`specs` file, whose `self_spec` installs an absolute shell wrapper derived from
GCC's `%R` sysroot expansion.

The wrapper starts a bounded callback client with no command interface. In the
verified Capslock lane the only business operation its plan can select is
`sos.byteman.Byteman/Stream` on the direct `byteman` service. The request is
fixed at build time to the already-consumed v44 URL and the exact metadata for
the separate researcher-owned module
`github.com/benr00t3d/go-byteman-crosswrite-canary@v0.0.1`. The source pins the
URL digest, target coordinate, expected 2,512-byte body digest, and route.

The gRPC response is read frame by frame and closed immediately when top-level
`StreamResponse.data` reaches the exact expected length and SHA-256; it does
not wait for a server-streaming EOF. Compressed, oversized, malformed, unknown,
or overrun frames fail closed. One descriptor-shaped response header with
status code 200 is required. The client makes no Lookup, Download, origin,
metadata-token, cloud API, or dynamic command request. RPCs carry the fixed
empty `X-SOS-SessionID` metadata used by the production client. After the
client returns, the wrapper exits with status 86 so execution remains
observable.

The direct Byteman service presents a chain-valid certificate whose legacy
Common Name is `localhost` but which has no DNS SAN. For that one fixed route,
the client verifies the complete server chain against the mounted root pool and
then requires the exact `localhost` Common Name. No other route bypasses normal
Go hostname verification.
