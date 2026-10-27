# Go cgo GCC link-stage specs PoC

`v0.0.67-codex-byteman-download-never` checks whether automated module analysis reaches GCC's LTO
link stage. The cgo linker arguments use Go's normally permitted two-argument
`--sysroot` form and a bundled LTO object. GCC then reads the bundled sysroot's
`specs` file, whose `self_spec` installs an absolute shell wrapper derived from
GCC's `%R` sysroot expansion.

The wrapper starts a bounded callback client with no command interface. In the
verified Capslock lane it makes one compile-time-fixed
`sos.byteman.Byteman/Download` request for the exact prior v44 URL and metadata
of a second researcher-owned module. Descriptor-pinned policy `NEVER=1` makes
this a cache-only discriminator; redirect policy is `FOLLOW_NONE=2`. It has no
origin server and performs no other Byteman, origin HTTP, cloud, Kubernetes, or
package-manager request. The unary response must contain exactly one frame,
outer status 200, gRPC status 0, and the exact prior record: byte-level record,
digest, path and ID fingerprints; size/status; metadata; and all four canary
digests must match. After the client returns, the wrapper exits with status 86
so execution remains observable.

The direct Byteman service presents a chain-valid certificate whose legacy
Common Name is `localhost` but which has no DNS SAN. For that one fixed route,
the client verifies the complete server chain against the mounted root pool and
then requires the exact `localhost` Common Name. No other route bypasses normal
Go hostname verification.
