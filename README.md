# v0.0.135-source-substitution-queue-codex

This is a held-back queue-only phase for the owned source-integrity test. It is
used only after v134 has independently verified the exact altered B record.

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
separate B worker. It is not published until the v134 write receipt is exact.
