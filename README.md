# Owned-B independent live cache reader

`v0.0.110-codex` independently tests live cross-worker cache integrity. It requires the
public `v0.0.5` coordinate of Robert's second
module, `github.com/benr00t3d/go-byteman-crosswrite-canary`.

At the GCC link stage, the fixed wrapper starts a compile-time-pinned reader.
Only when its origin is exactly this version's Capslock modcache directory does
it inspect B's fixed `canary.go`. It never writes. A positive result requires
the exact 366-byte A109 altered SHA-256 and marker in this independent worker.

The diagnostic has no command interface and does not inspect environment values,
credentials, processes, arbitrary paths, cloud resources, Kubernetes, or
internal RPC services. Generic builds stop before any marker read or network
request. The wrapper exits with status 86 after the verifier returns so the
analysis failure remains observable.
