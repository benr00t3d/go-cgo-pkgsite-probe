# v0.0.132-source-substitution-mutate-codex

This owned A/B test checks whether a download record written by A can change
the source consumed by a separate normal analysis of B.

The test uses `go-byteman-crosswrite-canary@v0.0.10`, whose canonical proxy
archive is inert and produces an empty capability list. The altered archive is
also inert, but contains one non-executed `os/exec` construction so the
analysis result has a deterministic `CAPABILITY_EXEC` marker.

The mutation sequence is:

1. A stores the altered B archive through one descriptor-pinned Byteman
   `Download(ALWAYS)` request.
2. A submits one `CapabilityAction(B)` to the normal Capslock input queue.
3. A waits briefly for B's public result to converge on the altered marker.

The altered record remains available for the independently queued B worker,
whose observed delay can exceed the lifetime of A's compiler process. A
separate canonical restoration version is held back until the altered marker
is observed or the bounded external monitor times out. Both archive and queue
requests are compiled and hash-pinned. The clients have no command interface
and target only Robert's two modules.
