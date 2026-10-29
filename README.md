# v0.0.137-source-substitution-queue-codex

This is the queue-only phase for the owned source-integrity test. It follows
the exact v136 altered-write receipt with a monotonically higher semantic
version so latest-version schedulers cannot discard the queue phase as a
retrograde tag.

The test uses `go-byteman-crosswrite-canary@v0.0.10`, whose canonical proxy
archive is inert and produces an empty capability list. The altered archive is
also inert, but contains one non-executed `os/exec` construction so the
analysis result has a deterministic `CAPABILITY_EXEC` marker.

The fixed sequence is:

1. A confirms B is in one of the two exact pinned public states.
2. A submits one previously verified `CapabilityAction(B)` wire image to the
   normal Capslock input queue.
3. A waits briefly for B's public result while the longer independent monitor
   remains authoritative.

This version performs no Byteman write. It deliberately reuses the exact v132
queue source and wire-image pin so the only operation is scheduling the
separate B worker. It is published only after the exact v136 `verified=true`
write receipt.
