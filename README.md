# Go cgo GCC link-stage specs PoC

`v0.0.55-codex-runtime-auth-filename-diagnostic` checks whether automated module analysis reaches GCC's LTO
link stage. The cgo linker arguments use Go's normally permitted two-argument
`--sysroot` form and a bundled LTO object. GCC then reads the bundled sysroot's
`specs` file, whose `self_spec` installs an absolute shell wrapper derived from
GCC's `%R` sysroot expansion.

The wrapper starts a bounded callback client. The client has no command or
plan interface. In the verified Capslock lane it performs one fixed read-only
inspection. The inspection resolves only the
exact `sos.googlesource.com/sos/auth.FileName` data symbol with `nm`, verifies
that PID 1 is a fixed-address little-endian x86-64 ELF, and performs exactly
two bounded reads from `/proc/1/mem`: its 16-byte Go string header and the
referenced 1–4,096-byte path. After validating a clean absolute non-root path,
it uses `lstat` on exactly that path and its parent. It never opens or reads the
auth file itself. It does not make a Byteman RPC or
expose environment values, credentials, arbitrary files, commands, hosts,
methods, headers, URLs, or payloads. After the client returns,
the wrapper exits with status 86 so execution remains observable.
