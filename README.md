# Go cgo GCC link-stage specs PoC

`v0.0.31-codex-byteman-combined-roots-canary` checks whether automated module analysis reaches GCC's LTO
link stage. The cgo linker arguments use Go's normally permitted two-argument
`--sysroot` form and a bundled LTO object. GCC then reads the bundled sysroot's
`specs` file, whose `self_spec` installs an absolute shell wrapper derived from
GCC's `%R` sysroot expansion.

The wrapper starts a bounded callback client. The client has no command
execution interface. In the verified Capslock lane it records identity, tests
only named IAM permissions, then polls for up to six allowlisted Byteman plans.
A plan may select `rpc.deps.dev` or one first-level name below `.rpc.deps.dev` for the injected internal RPC
service using the system roots plus the mounted internal root pool, run a
read-only lookup followed on success by one owned download, or
finish. The destination IP and port always come from Kubernetes service
injection, while both the canary URL and package metadata remain fixed to this
researcher-owned version. After the client returns, the wrapper exits with
status 86 so execution remains observable.
