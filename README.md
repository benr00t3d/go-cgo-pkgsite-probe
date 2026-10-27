# Go cgo GCC link-stage specs PoC

`v0.0.26-codex` checks whether automated module analysis reaches GCC's LTO
link stage. The cgo linker arguments use Go's normally permitted two-argument
`--sysroot` form and a bundled LTO object. GCC then reads the bundled sysroot's
`specs` file, whose `self_spec` installs an absolute shell wrapper derived from
GCC's `%R` sysroot expansion.

The wrapper runs the bundled, standalone `poc.sh` once. The script is restricted
to the expected root Capslock worker and Robert's owned module. It records a
public deps.dev baseline, submits one error-only result for the owned v0.0.22
record, observes the public hash change, requests Refresh, and waits for the
baseline to return. It has no callback client or callback configuration.
