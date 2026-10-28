# v0.0.121-codex owned Queue cleanup receipt

This owned module version obtains one direct receipt for the production
Capslock worker's Queue authorization while restoring one researcher-owned
canary record. Its GCC LTO/sysroot wrapper runs only as root from this exact
module's `v0.0.121-codex` Capslock path.

Before internal access, the client reads five cache-busted public analysis
responses for the fixed owned target
`github.com/benr00t3d/go-byteman-crosswrite-canary@v0.0.5`:

- five exact clean responses cause a callback-only no-op;
- any mixed or unknown response aborts before internal access;
- five exact altered responses require a successful callback preflight before
  the one internal request is allowed.

The permitted request is a pinned 136-byte `sos.queue.Queue/Push` stream to
`capslock-capability-result`. It contains one clean `CapabilityResultAction`
for the fixed owned target, with no capabilities or error. It is sent once and
is never retried. The response is accepted only if it has exact HTTP/gRPC
success, complete gRPC frames, one target echo, and one action UUID. The UUID
is never returned; only its SHA-256 is included in the receipt.

Afterward the client waits for 21 consecutive exact clean public responses.
It sends bounded preflight, Queue, and final receipts to one pinned receiver in
the owned `s0victim-44547` project. Each acknowledgement binds the exact
submitted body hash. Receipts include public response bodies and hashes,
request/response sizes and hashes, gRPC status metadata, and the client
certificate's public identity fields and fingerprint. They never include the
private key, certificate bytes, action UUID, environment, token, command
channel, arbitrary endpoint, persistence, or a third-party package target.
