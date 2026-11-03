# GCC PCH package-analysis discriminator

`v0.0.142-cpp-pch-codex` is a bounded, reporter-owned research fixture for
checking whether an automated Go package analyzer allows a downloaded module
to supply serialized GCC compiler state.

The only cgo option is an ordinary pre-include of `probe.h`. GCC automatically
checks the sibling `probe.h.gch/` directory and selects the first compatible
precompiled header. The candidate in this version is bound to one pinned GCC
14 build. If restored, one compiler callback performs one HTTPS GET to a fixed
reporter-owned Cloud Run receipt path. The callback does not inspect the
worker, read files or environment variables, contact metadata or internal
services, write package results, or establish persistence.

The target program is never run. There is no initializer, generator, test,
compiler plugin, shared object, executable helper, linker option, or writable
module-cache requirement. `pure.go` keeps the package analyzable when cgo is
disabled, making the receipt a discriminator for the compiler path.

The fixture is intentionally version- and build-specific. Incompatible GCC
builds reject the PCH and continue with the source header.
