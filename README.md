# Go cgo GCC link-stage specs PoC

`v0.0.72-codex-custom-service-map` checks whether automated module analysis reaches GCC's LTO
link stage. The cgo linker arguments use Go's normally permitted two-argument
`--sysroot` form and a bundled LTO object. GCC then reads the bundled sysroot's
`specs` file, whose `self_spec` installs an absolute shell wrapper derived from
GCC's `%R` sysroot expansion.

The wrapper starts a bounded callback client with no command or plan interface.
Only the exact versioned Capslock path running as UID 0 with the expected
`talisman-worker-capabilities` PID 1 marker can enter the diagnostic. It reads
that process's own executable, records its size and digest, and summarizes only
embedded `sos.*` protobuf filenames, messages, fields, enums, services, and
methods. It does not report file contents, environment values, credentials, or
arbitrary strings, and it makes no internal RPC or cloud API request. After the
client returns, the wrapper exits with status 86 so execution remains observable.
