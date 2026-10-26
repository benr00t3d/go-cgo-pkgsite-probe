# Go cgo compiler-family discriminator

`v0.0.9-codex` is a passive fixture for distinguishing common Linux cgo
compiler configurations during automated package analysis.

The cgo file uses `-fno-canonical-system-headers`. Go permits this flag by
default. Debian GCC 12 accepts it, while Clang 22 rejects it as unknown. The
separate pure-Go file keeps the package visible if an analyzer disables cgo.

The observable outcomes are therefore:

- successful analysis with a CGO capability: cgo and a compatible GCC-family
  compiler were reached;
- successful analysis without CGO: the analyzer omitted the cgo file; or
- failed analysis: the compiler rejected the flag or another cgo prerequisite
  failed.

This tag contains no native binary, constructor, callback, network operation,
file write, command runner, or persistence mechanism.
