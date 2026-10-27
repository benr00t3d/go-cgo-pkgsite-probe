# Owned-B cross-job content consumer

`v0.0.103-codex` is a bounded follow-up to the `v0.0.68-codex` owned-content
ingestion test. It requires the public `v0.0.2` coordinate of Robert's second
module, `github.com/benr00t3d/go-byteman-crosswrite-canary`.

At the GCC link stage, the fixed wrapper starts a compile-time-pinned diagnostic.
Only when its origin is exactly this version's Capslock modcache directory does
the diagnostic inspects only B's fixed altered-marker path and fixed canonical
`canary.go` path. It submits their type/size/SHA-256 states in one JSON receipt,
so canonical and altered selection are distinguishable without returning file content.

The diagnostic has no command interface and does not inspect environment values,
credentials, processes, arbitrary paths, cloud resources, Kubernetes, or
internal RPC services. Generic builds stop before any marker read or network
request. The wrapper exits with status 86 after the verifier returns so the
analysis failure remains observable.
