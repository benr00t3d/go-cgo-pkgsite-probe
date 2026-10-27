# Go cgo GCC link-stage specs PoC

`v0.0.68-codex-byteman-content-ingest` checks whether automated module analysis reaches GCC's LTO
link stage. The cgo linker arguments use Go's normally permitted two-argument
`--sysroot` form and a bundled LTO object. GCC then reads the bundled sysroot's
`specs` file, whose `self_spec` installs an absolute shell wrapper derived from
GCC's `%R` sysroot expansion.

The wrapper starts a bounded callback client with no command interface. In the
verified Capslock lane it makes exactly one compile-time-fixed
`sos.byteman.Byteman/Download` request for an inert altered archive of a second
researcher-owned module. Descriptor-pinned policy is `ALWAYS=4`; redirect policy
is `FOLLOW_NONE=2`. It performs no Lookup, Stream, Queue, Talisman, Pacman,
cloud-data, Kubernetes, or arbitrary-command action. The unary response must
contain one exact B record with status 200, gRPC status 0, exact coordinate and
all four altered-archive digests. After the client returns, the wrapper exits
with status 86 so execution remains observable.

The direct Byteman service presents a chain-valid certificate whose legacy
Common Name is `localhost` but which has no DNS SAN. For that one fixed route,
the client verifies the complete server chain against the mounted root pool and
then requires the exact `localhost` Common Name. No other route bypasses normal
Go hostname verification.
