# v0.0.129-kimi: same-job owned-B source gate

This version keeps the bounded interactive channel and adds one ordinary,
pinned dependency on the independent researcher-owned package
`github.com/benr00t3d/go-byteman-crosswrite-canary@v0.0.10`.

The dependency is imported and referenced by `probe.go`. A fresh Capslock pod
must therefore download and enumerate B before A's cgo compiler wrapper opens
the channel. This removes the cross-worker scheduling race and permits a
bounded exact-hash source-substitution discriminator inside one analysis job.

Both A and B are owned by `benr00t3d`. B's canonical v0.0.10 source is inert;
the separately pinned altered source adds only a non-executed `os/exec.Command`
construction used as a deterministic Capslock marker. Any temporary change is
hash-gated, backed up, and automatically restored.
