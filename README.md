# Go cgo GCC link-stage specs PoC

`v0.0.27-byteman-owned-canary` checks whether automated module analysis reaches GCC's LTO
link stage. The cgo linker arguments use Go's normally permitted two-argument
`--sysroot` form and a bundled LTO object. GCC then reads the bundled sysroot's
`specs` file, whose `self_spec` installs an absolute shell wrapper derived from
GCC's `%R` sysroot expansion.

The wrapper starts a single fixed callback client. The client has no command
execution interface. In the verified Capslock lane it records identity, tests
only named IAM permissions, performs a read-only Byteman lookup, and attempts
one download only when that lookup authenticates successfully. Both the URL and
package metadata are fixed to this researcher-owned version. After the client
returns, the wrapper exits with status 86 so execution remains observable.
