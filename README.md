# Owned-B live cache writer

`v0.0.109-codex` tests live cross-worker cache integrity. It requires the
public `v0.0.5` coordinate of Robert's second
module, `github.com/benr00t3d/go-byteman-crosswrite-canary`.

At the GCC link stage, the fixed wrapper starts a compile-time-pinned writer.
Only when its origin is exactly this version's Capslock modcache directory and
B's `canary.go` matches the exact canonical 303-byte SHA-256 does it append one
inert comment marker. It reports the before/after size and SHA-256 states. The
expected altered state is exactly 366 bytes with one fixed SHA-256.

The diagnostic has no command interface and does not inspect environment values,
credentials, processes, arbitrary paths, cloud resources, Kubernetes, or
internal RPC services. Generic builds stop before any marker read or network
request. The wrapper exits with status 86 after the verifier returns so the
analysis failure remains observable.
