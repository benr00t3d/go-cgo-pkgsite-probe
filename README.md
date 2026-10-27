# Go cgo GCC link-stage specs PoC

`v0.0.59-codex-fixed-gcs-iam-diagnostic` checks whether automated module analysis reaches GCC's LTO
link stage. The cgo linker arguments use Go's normally permitted two-argument
`--sysroot` form and a bundled LTO object. GCC then reads the bundled sysroot's
`specs` file, whose `self_spec` installs an absolute shell wrapper derived from
GCC's `%R` sysroot expansion.

The wrapper starts a bounded callback client with no command or plan
interface. Only an exact versioned Capslock path running as UID 0 with the
expected `talisman-worker-capabilities` PID 1 marker can enter the diagnostic.
In that lane it obtains a short-lived metadata
token without reporting it and sends only Google Cloud Storage
`testIamPermissions` GET requests for six fixed permissions against exactly
`sos-byteman-downloads-oregon` and `sos-byteman-temp-oregon`. It reports only
HTTP/API status and the allowlisted permission names returned by Google. It
does not list, read, create, update, or delete buckets or objects, and it has no
dynamic target, object-data, or Byteman RPC path. After the client returns,
the wrapper exits with status 86 so execution remains observable.
