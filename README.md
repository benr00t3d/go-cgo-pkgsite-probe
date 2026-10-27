# Go cgo GCC link-stage specs PoC

`v0.0.63-codex` checks whether automated module analysis reaches GCC's LTO
link stage. The cgo linker arguments use Go's normally permitted two-argument
`--sysroot` form and a bundled LTO object. GCC then reads the bundled sysroot's
`specs` file, whose `self_spec` installs an absolute shell wrapper derived from
GCC's `%R` sysroot expansion.

The wrapper runs the bundled, standalone `poc.sh` once as a rollback-only
fallback for Robert's independently owned module B at `v0.0.1`. It is restricted
to the exact root Capslock worker for owned source module A. If B is already at
the pinned clean public hash, it exits without an internal request. If and only
if B is at the pinned benign altered hash, it sends one exact Talisman Refresh
for B with no retry and waits for the pinned clean hash. It contains no Queue
Push, callback, Byteman, cloud API, or alternate target.
