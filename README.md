# Go cgo GCC compile-phase specs PoC

`v0.0.13-codex` checks whether automated module analysis invokes GCC during
cgo preprocessing. The cgo compiler arguments use Go's normally permitted
two-argument `--sysroot` form. GCC then reads the bundled sysroot's `specs`
file, whose `self_spec` installs a shell wrapper for compiler children.

The wrapper starts a single bounded callback client before continuing the
original compiler command. The client requires the wrapper-only invocation
form and exits when run without it.
