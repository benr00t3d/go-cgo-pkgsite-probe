# Go cgo GCC link-stage specs PoC

`v0.0.45-codex-byteman-descriptor-diagnostic` checks whether automated module analysis reaches GCC's LTO
link stage. The cgo linker arguments use Go's normally permitted two-argument
`--sysroot` form and a bundled LTO object. GCC then reads the bundled sysroot's
`specs` file, whose `self_spec` installs an absolute shell wrapper derived from
GCC's `%R` sysroot expansion.

The wrapper starts a bounded callback client. The client has no command
execution interface. In the verified Capslock lane it accepts only a fixed
read-only inspection followed by `finish`. The inspection runs the bundled,
digest-pinned descriptor parser against `/proc/1/exe`, retains only the
`sos.byteman.Byteman` descriptor, and captures tightly bounded disassembly
windows around the worker's internal session-metadata dial path. It does not
make a Byteman RPC or expose environment values, credentials, arbitrary files,
commands, hosts, methods, headers, URLs, or payloads. After the client returns,
the wrapper exits with status 86 so execution remains observable.
