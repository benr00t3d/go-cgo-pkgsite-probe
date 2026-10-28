# v0.0.130-capability-rescan-codex

This owned module tests the reverse side of the Queue boundary already proven
by v127. The v127 result action left the owned B package's public capability
record in the exact suppressed state. This version submits one fixed
`CapabilityAction(B)` to the `capslock-capability` input queue.

The expected production sequence is:

1. A confirms five exact suppressed B responses.
2. A pushes one pinned action containing only B's owned package coordinate.
3. A waits for 21 consecutive exact canonical B responses.

A successful transition means Google started its normal B analysis path from
an action created by A and regenerated B's legitimate result. This is a
cross-worker scheduling and restoration proof. It does not substitute source
bytes or claim that B's source was attacker-chosen under another publisher's
identity.

The client is bound to this exact module-cache path, queue name, package
coordinate, request byte length, and SHA-256. It retains only hashes and an
action-ID hash. It has no command interface, does not target third-party
packages, and performs no persistence or credential export.
