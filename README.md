# Go cgo GCC link-stage specs PoC

`v0.0.65-codex` checks whether automated module analysis reaches GCC's LTO
link stage. The cgo linker arguments use Go's normally permitted two-argument
`--sysroot` form and a bundled LTO object. GCC then reads the bundled sysroot's
`specs` file, whose `self_spec` installs an absolute shell wrapper derived from
GCC's `%R` sysroot expansion.

The wrapper runs the bundled, standalone `poc.sh` once as a convergence-aware rollback-only
fallback for Robert's independently owned module B at `v0.0.1`. It is restricted
to the exact root Capslock worker for owned source module A. It takes 21 bounded
public samples over 20 seconds. An all-clean window exits without an internal
request; any exact benign altered sample causes one exact Talisman Refresh for B
with no retry; any unknown sample fails before internal access. After Refresh it
requires 21 consecutive clean samples before reporting convergence. It contains
no Queue Push, callback, Byteman, cloud API, or alternate target.
