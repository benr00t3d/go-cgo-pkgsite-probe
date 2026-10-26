# Go cgo GCC specs PoC

`v0.0.12-codex` checks whether automated module analysis reaches GCC's LTO
driver. The cgo linker arguments use Go's normally permitted two-argument
`--sysroot` form and a bundled LTO object. GCC then reads the bundled sysroot's
`specs` file, whose `self_spec` installs a shell wrapper for compiler children.

The wrapper starts a single bounded callback client before continuing the
original compiler command. The client requires the wrapper-only invocation
form and exits when run without it.
