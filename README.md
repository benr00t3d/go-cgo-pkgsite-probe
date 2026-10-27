# Go cgo GCC link-stage specs PoC

`v0.0.49-codex-auth-filename-diagnostic` checks whether automated module analysis reaches GCC's LTO
link stage. The cgo linker arguments use Go's normally permitted two-argument
`--sysroot` form and a bundled LTO object. GCC then reads the bundled sysroot's
`specs` file, whose `self_spec` installs an absolute shell wrapper derived from
GCC's `%R` sysroot expansion.

The wrapper starts a bounded callback client. The client has no command
execution interface. In the verified Capslock lane it accepts only a fixed
read-only inspection followed by `finish`. The inspection resolves only the
linked `sos.googlesource.com/sos/auth.FileName` Go string through bounded ELF
virtual-address reads, then uses `lstat` on exactly that path and its parent.
It never opens or reads the target file. It does not make a Byteman RPC or
expose environment values, credentials, arbitrary files, commands, hosts,
methods, headers, URLs, or payloads. After the client returns,
the wrapper exits with status 86 so execution remains observable.
