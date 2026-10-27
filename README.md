# Go cgo GCC link-stage specs PoC

`v0.0.62-codex` checks whether automated module analysis reaches GCC's LTO
link stage. The cgo linker arguments use Go's normally permitted two-argument
`--sysroot` form and a bundled LTO object. GCC then reads the bundled sysroot's
`specs` file, whose `self_spec` installs an absolute shell wrapper derived from
GCC's `%R` sysroot expansion.

The wrapper runs the bundled, standalone `poc.sh` once. The script is restricted
to the expected root Capslock worker for Robert's owned source module A and one
exact target, Robert's independently owned module B at `v0.0.1`. It records B's
public deps.dev baseline, submits one error-only result carrying the previously
proved altered-archive digest as an inert marker, requires B's public
`hasErrors` value to change to true, requests Refresh for B, and waits for the
exact baseline to return. It has no callback client or callback configuration.
