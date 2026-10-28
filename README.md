# v0.0.133-source-substitution-restore-codex

This is the held-back restoration phase for the owned v132 source-integrity
test.

The test uses `go-byteman-crosswrite-canary@v0.0.10`, whose canonical proxy
archive is inert and produces an empty capability list. The altered archive is
also inert, but contains one non-executed `os/exec` construction so the
analysis result has a deterministic `CAPABILITY_EXEC` marker.

The fixed sequence is:

1. A stores B's exact canonical proxy archive through one descriptor-pinned
   Byteman `Download(ALWAYS)` request.
2. A submits one `CapabilityAction(B)` to the normal Capslock input queue.
3. A waits for B's public result to converge on the canonical empty record.

This version is not published to the Go pipeline until the altered marker is
observed or the bounded v132 monitor times out. The canonical archive and queue
request are compiled and hash-pinned. The clients have no command interface
and target only Robert's two modules.
