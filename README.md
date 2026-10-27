# Go cgo GCC link-stage specs PoC

`v0.0.47-codex-session-dataflow-diagnostic` checks whether automated module analysis reaches GCC's LTO
link stage. The cgo linker arguments use Go's normally permitted two-argument
`--sysroot` form and a bundled LTO object. GCC then reads the bundled sysroot's
`specs` file, whose `self_spec` installs an absolute shell wrapper derived from
GCC's `%R` sysroot expansion.

The wrapper starts a bounded callback client. The client has no command
execution interface. In the verified Capslock lane it accepts only a fixed
read-only inspection followed by `finish`. The inspection captures a bounded
disassembly slice of only `sos.googlesource.com/sos/server.dial` and resolves
only its fixed 15-byte `X-SOS-SessionID` read-only ELF literal. It does not
make a Byteman RPC or expose environment values, credentials, arbitrary files,
commands, hosts, methods, arbitrary headers, URLs, or payloads. After the client returns,
the wrapper exits with status 86 so execution remains observable.
