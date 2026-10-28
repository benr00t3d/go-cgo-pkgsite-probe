# v0.0.124-codex owned Queue roundtrip

This module prepares an attributable write-and-restore test against a fresh
researcher-owned package-analysis record. Its GCC LTO/sysroot wrapper runs only
as root from this exact module's `v0.0.124-codex` Capslock path.

Before internal access, the client reads five cache-busted public analysis
responses for the fixed owned target
`github.com/benr00t3d/go-byteman-crosswrite-canary@v0.0.8`. Five exact clean
responses and a successful callback preflight are required before internal
access. Mixed, unknown, or already-mutated responses abort.

The test uses two separately pinned `sos.queue.Queue/Push` streams. The first
writes one unique structured capability result and waits for 21 consecutive
exact public responses. The second restores the empty clean result and waits
for 21 consecutive exact clean responses. Each response must have HTTP/gRPC
success, complete gRPC frames, one target echo, and one action UUID. Receipts
contain only the UUID hash.

The mutation builder and its pins are intentionally disabled until the v123
production descriptor supplies the exact nested capability schema. With the
placeholder pins in this branch, the client returns before any callback or
internal request.

Bounded preflight, mutation, public-transition, cleanup, and final receipts go
to one pinned receiver in the owned `s0victim-44547` project. Each
acknowledgement binds the submitted body hash. No third-party target, arbitrary
endpoint, credential export, command channel, or persistence is present.
