# v0.0.139

This is the stable-version fallback for the owned source-integrity test. It
uses the same combined phase as v138 and removes the need for two independently
scheduled A workers.

The test uses `go-byteman-crosswrite-canary@v0.0.10`, whose canonical proxy
archive is inert and produces an empty capability list. The altered archive is
also inert, but contains one non-executed `os/exec` construction so the
analysis result has a deterministic `CAPABILITY_EXEC` marker.

One A worker performs this fixed sequence:

1. Store the exact altered B archive through one descriptor-pinned Byteman
   `Download(ALWAYS)` request.
2. Require the exact altered record and callback receipt to verify.
3. Only on that success, submit one pinned `CapabilityAction(B)` to the normal
   Capslock input queue.
4. Leave the altered record in place for the separately scheduled B worker.

This version performs no restoration. The held v133 version restores B after
the public marker or bounded observation window. Both clients have no command
interface and target only Robert's two modules.
