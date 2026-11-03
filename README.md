# v0.0.140-sumd: Capslock checksum-route discriminator

This version contains one ordinary pinned dependency on the independent,
researcher-owned package
`github.com/benr00t3d/go-byteman-crosswrite-canary@v0.0.10`.

The dependency is imported and referenced by `probe.go`, but this version
intentionally does not publish a `go.sum`. A fresh analysis must therefore
either authenticate B through its effective Go checksum configuration or fail
closed before compilation. If compilation is reached, the existing bounded
research channel records only allowlisted Go routing values and owned-module
cache provenance.

Both A and B are owned by `benr00t3d`. B's canonical source is inert. This
version performs no credential reads, service writes, package substitution, or
requests for third-party module identities.
