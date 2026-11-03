# v0.0.141-sumc: Capslock checksum-route control

This version contains one ordinary pinned dependency on the independent,
researcher-owned package
`github.com/benr00t3d/go-byteman-crosswrite-canary@v0.0.10`.

The dependency is imported and referenced by `probe.go`. Unlike the matched
`v0.0.140-sumd` discriminator, this control publishes B's canonical `go.sum`
entries. It tests whether the current Capslock lane schedules and reaches the
same compiler wrapper without requiring a fresh checksum lookup.

Both A and B are owned by `benr00t3d`. B's canonical source is inert. This
version performs no credential reads, service writes, package substitution, or
requests for third-party module identities.
