# v0.0.131-source-substitution-codex

This owned A/B test checks whether a download record written by A can change
the source consumed by a separate normal analysis of B.

The test uses `go-byteman-crosswrite-canary@v0.0.10`, whose canonical proxy
archive is inert and produces an empty capability list. The altered archive is
also inert, but contains one non-executed `os/exec` construction so the
analysis result has a deterministic `CAPABILITY_EXEC` marker.

The fixed sequence is:

1. A stores the altered B archive through one descriptor-pinned Byteman
   `Download(ALWAYS)` request.
2. A submits one `CapabilityAction(B)` to the normal Capslock input queue.
3. A waits for B's public result to converge on the altered marker.
4. A stores B's exact canonical proxy archive through the same bounded path.
5. A schedules B again and waits for the canonical empty result to return.

The test succeeds only if the altered result and the final restoration each
appear for 21 consecutive samples. Both archives, both package coordinates,
both queue requests, and all callback paths are compiled and hash-pinned. The
clients have no command interface and target only Robert's two modules.
