# v66 clean-result wire basis

This unpublished contingency uses only the exact owned target
`github.com/benr00t3d/go-byteman-crosswrite-canary@v0.0.1`.

Observed descriptor evidence from the pinned v0.0.22 Capslock worker binary on
2026-10-26 established:

- `sos.queue.Queue/Push` is bidirectional streaming.
- `sos.queue.PushRequest.action` is field 1.
- `sos.queue.Action.queue`, `.payload`, and `.source` are fields 1, 3, and 4.
- `sos.talisman.CapabilityResultAction.package_version`, `.capabilities`, and
  `.error` are fields 1, 2, and 3; capabilities is repeated and error is a
  string.

The pinned v0.0.26 source and its production receipt established the required
two-request stream shape: one Action carrying queue/source, then one Action
carrying the serialized CapabilityResultAction in payload. Its fields 1+3
error-only action was accepted and later produced the exact public
`capabilities:[], hasErrors:true` representation.

The v66 payload is exactly field 1 plus the 56-byte owned target (58 bytes,
SHA-256 `bab053bb0a1de3b8e3b0e69eb4fc95aa29ebe76053a122d9bccfb0eabaeeb5a6`).
Under proto3, omitting repeated field 2 decodes as an empty capability map and
omitting string field 3 decodes as an empty error. That is the serialized form
of a zero-capability successful result and predicts B's pinned exact clean
public representation.

The full two-frame request is 136 bytes with SHA-256
`fe5533010712656f62536a6e4f3aa6cd4fa1de6453cca061acb71d3e72f6175b`.

Evidence boundary: the field layout, defaults, framing, and v26 error-path
consumption are observed. A field-1-only result has not itself been submitted
by this research harness, so acceptance and exact clean public convergence are
a strongly supported prediction rather than an observed v66 result. For that
reason this draft must remain unpublished and untriggered unless separately
reviewed and explicitly approved.
