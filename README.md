# Go cgo GCC link-stage specs PoC

`v0.0.70-codex-pkgsite-lane-boundary` checks whether automated module analysis reaches GCC's LTO
link stage. The cgo linker arguments use Go's normally permitted two-argument
`--sysroot` form and a bundled LTO object. GCC then reads the bundled sysroot's
`specs` file, whose `self_spec` installs an absolute shell wrapper derived from
GCC's `%R` sysroot expansion.

The wrapper starts a bounded callback client with no command interface. It sends an immediate
execution receipt, then in the pkg.go.dev build lane records only process identity, credential-presence
booleans, credential-file metadata, fixed DNS lookups, Unix socket paths, and
fixed health-check statuses. It never records credential values and does not
invoke any mutating endpoint. Other execution lanes stop without probing.
