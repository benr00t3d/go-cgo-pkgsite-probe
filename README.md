# Go cgo GCC link-stage specs PoC

`v0.0.58-codex-byteman-coordinate-lookup` checks whether automated module analysis reaches GCC's LTO
link stage. The cgo linker arguments use Go's normally permitted two-argument
`--sysroot` form and a bundled LTO object. GCC then reads the bundled sysroot's
`specs` file, whose `self_spec` installs an absolute shell wrapper derived from
GCC's `%R` sysroot expansion.

The wrapper starts a bounded callback client with no command interface. In the
verified Capslock lane it makes one compile-time-fixed, read-only
`sos.byteman.Byteman/Lookup` request for the researcher-owned Go module,
version, registry, and a limit of 32 records. It performs no Stream, Download,
origin HTTP, cloud, or Kubernetes request. The server stream is parsed one gRPC
frame at a time and closes immediately on the exact prior v44 record: byte-level
record, digest, path and ID fingerprints; size/status; metadata; and all four
canary digests must match. After the client returns, the wrapper exits with
status 86 so execution remains observable.

The direct Byteman service presents a chain-valid certificate whose legacy
Common Name is `localhost` but which has no DNS SAN. For that one fixed route,
the client verifies the complete server chain against the mounted root pool and
then requires the exact `localhost` Common Name. No other route bypasses normal
Go hostname verification.
