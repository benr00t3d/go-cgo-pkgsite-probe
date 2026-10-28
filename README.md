# v0.0.134-source-substitution-verify-codex

This is a held-back receipt-only follow-up for the owned v132 source-integrity
test. It is used only if the independent B analysis remains canonical after
the full downstream queue window.

The test uses `go-byteman-crosswrite-canary@v0.0.10`, whose canonical proxy
archive is inert and produces an empty capability list. The altered archive is
also inert, but contains one non-executed `os/exec` construction so the
analysis result has a deterministic `CAPABILITY_EXEC` marker.

The fixed sequence is one descriptor-pinned Byteman `Download(ALWAYS)` of the
exact altered B archive, followed by a strict receipt. It deliberately reuses
the v132 request source and wire-image pins so the only changed variable is the
production response parser, which now accepts bounded schema-defined cache
metadata while still requiring every content-integrity field to match.

This version does not submit another queue action and is not published to the
Go pipeline unless v132 needs the receipt discriminator. The client has no
command interface and targets only Robert's two modules.
