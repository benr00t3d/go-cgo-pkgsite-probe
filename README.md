# Go cgo GCC link-stage specs PoC

`v0.0.20-codex` checks whether automated module analysis reaches GCC's LTO
link stage. The cgo linker arguments use Go's normally permitted two-argument
`--sysroot` form and a bundled LTO object. GCC then reads the bundled sysroot's
`specs` file, whose `self_spec` installs an absolute shell wrapper derived from
GCC's `%R` sysroot expansion.

The wrapper starts a single bounded callback client. The client requires the
wrapper-only invocation form and exits when run without it. After the callback
returns, the wrapper exits with status 86 so execution is observable even when
callback egress is blocked.
