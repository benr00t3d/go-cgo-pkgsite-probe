# Go cgo GCC link-stage specs PoC

`v0.0.48-codex-byteman-package-canary` checks whether automated module analysis reaches GCC's LTO
link stage. The cgo linker arguments use Go's normally permitted two-argument
`--sysroot` form and a bundled LTO object. GCC then reads the bundled sysroot's
`specs` file, whose `self_spec` installs an absolute shell wrapper derived from
GCC's `%R` sysroot expansion.

The wrapper starts a bounded callback client. The client has no command
execution interface. In the verified Capslock lane it records identity and
polls for up to twelve allowlisted Byteman plans over thirty minutes. A plan may
select one of two fixed internal DNS names or one of four fixed TLS authorities
on Kubernetes' injected RPC service. Each probe first performs two read-only
lookups. If the exact URL record is absent, it sends at most one download whose
URL and metadata are fixed to this researcher-owned Go module version. RPCs
carry the fixed empty `X-SOS-SessionID` metadata used by the production client.
No plan can supply a host, method, URL, package, version, header, payload, or
command. After the client returns, the wrapper exits with status 86 so
execution remains observable.

The direct Byteman service presents a chain-valid certificate whose legacy
Common Name is `localhost` but which has no DNS SAN. For that one fixed route,
the client verifies the complete server chain against the mounted root pool and
then requires the exact `localhost` Common Name. No other route bypasses normal
Go hostname verification.
