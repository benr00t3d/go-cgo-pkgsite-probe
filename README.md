# v0.0.127 capability-suppression and restoration discriminator

This module prepares an attributable capability-suppression test against a
fresh researcher-owned package-analysis record. Its GCC LTO/sysroot wrapper
runs only as root from this exact module's production Capslock path.

Before internal access, the client reads five cache-busted public analysis
responses for the fixed owned target
`github.com/benr00t3d/go-byteman-crosswrite-canary@v0.0.8`. That immutable
module intentionally contains one inert `os/exec.Command` call, so its normal
Google analysis has a non-empty EXEC capability. Five exact canonical responses
and a successful callback preflight are required before internal access.

The test sends one field-1-only `CapabilityResultAction` through the already
proven `sos.queue.Queue/Push` path. Success requires the legitimate non-empty
record to become exact empty capability metadata for 21 consecutive
cache-busted responses. The Queue response must have HTTP/gRPC success, two
complete frames, one target echo, and one action UUID. Receipts retain only the
UUID hash.

The production descriptor proves that `package_version` is field 1. A
field-1-only action was accepted in v121 and represents an empty successful
result. Using it here tests suppression without guessing any opaque value.
The 144-byte request and its digest are independently pinned in tests.

The canonical non-empty target body was pinned only after 21 consecutive
production responses. After retaining the suppression proof, the same bounded
run sends one descriptor-correct `sos.talisman.Talisman/Refresh` request. It
does not retry an ambiguous Refresh result. Success additionally requires HTTP
and gRPC acceptance of the exact 103-byte frame and 21 consecutive responses
showing the original non-empty record restored.

Six linked receipts go to one receiver in the owned project: preflight, Queue,
public suppression, Refresh, public restoration, and final. The final success
verdict requires both the cross-package suppression and restoration chains.
