# v0.0.136-source-substitution-verify-codex

This is the immutable follow-up to the v134 altered Download receipt. It keeps
the production-schema optional metadata fix and accepts a bounded variable
response-header count while preserving exact content-integrity checks.

The test uses `go-byteman-crosswrite-canary@v0.0.10`, whose canonical proxy
archive is inert and produces an empty capability list. The altered archive is
also inert, but contains one non-executed `os/exec` construction so the
analysis result has a deterministic `CAPABILITY_EXEC` marker.

The fixed sequence is one descriptor-pinned Byteman `Download(ALWAYS)` of the
exact altered B archive, followed by a strict receipt. It deliberately reuses
the v132 request source and wire-image pins.

This version performs no queue action. v135 remains held until this version
returns a version-pinned `verified=true` write receipt.
