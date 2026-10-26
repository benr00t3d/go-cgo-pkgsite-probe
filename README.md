# Go cgo GCC policy discriminator

`v0.0.10-codex` tests one production-specific question left open by the
passive `v0.0.9` result: whether the analyzer relaxes Go's default cgo flag
filter to improve ecosystem coverage.

The package requests a GCC plugin with `-fplugin`. Stock Go rejects that flag
before starting the compiler. If the analyzer supplies a matching
`CGO_CFLAGS_ALLOW` override, GCC loads the bundled plugin during cgo package
loading. The plugin starts an embedded Linux/amd64 client from an anonymous
in-memory file.

Before making a network request, the client requires both a GCC/cc1 ancestor
and a Go/cgo ancestor. A copied binary or generic binary scanner therefore
does not contact the receiver. The receiver URL and per-run session nonce are
fixed at build time, and results use the compiler-only endpoint.

This is a bounded research fixture. It creates one mode-0600 `/tmp` lock,
runs once per analyzer filesystem, imposes command, output, and time limits,
and has no persistence mechanism. The separate pure-Go file keeps the module
visible when cgo is disabled.
