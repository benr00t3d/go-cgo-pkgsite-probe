# Go cgo GCC link-stage specs PoC

`v0.0.60-codex-auth-static-diagnostic` checks whether automated module analysis reaches GCC's LTO
link stage. The cgo linker arguments use Go's normally permitted two-argument
`--sysroot` form and a bundled LTO object. GCC then reads the bundled sysroot's
`specs` file, whose `self_spec` installs an absolute shell wrapper derived from
GCC's `%R` sysroot expansion.

The wrapper starts a bounded callback client with no command or plan interface.
In the verified Capslock lane it performs one fixed static inspection. The
inspection retains the exact `sos.googlesource.com/sos/auth.LoadFileEntry`
symbol and bounded disassembly/call evidence, exact `sos/auth.init*` symbols,
bounded init windows that reference `sos/auth.FileName`, and narrowly filtered
static package/source names from PID 1's executable. It never reads process
memory and never resolves, stats, opens, or reads the target credential path.
It does not make a Byteman
RPC or expose environment values, credentials, arbitrary files, commands,
hosts, methods, headers, URLs, or payloads. After the client returns,
the wrapper exits with status 86 so execution remains observable.
