# Go ingestion capability probe

`v0.0.6-codex` is a bounded research fixture for checking whether a public Go
module is compiled during automated package analysis and what isolation is
visible to that compiler process.

The package contains a cgo `-target` operand and a matching target-derived
Clang configuration. If an affected Clang processes the package, the
configuration loads an ELF constructor. The constructor copies the bundled
non-executable helper to a private mode-0700 temporary file, runs it once,
waits, and removes the copy.

The helper performs one bounded round trip:

1. Fetch a versioned JSON plan through an object-specific, expiring signed URL.
2. Reject unknown fields, duplicate probes, unknown probe names, or more than
   seven probes.
3. Run only the selected built-in probes.
4. Upload one typed JSON receipt through a second object-specific, expiring
   signed URL.

The built-in probes report process ancestry classes, coarse runtime and
sandbox state, temporary write/delete results, metadata-network reachability,
and presence/openability of fixed workload-identity locations. The metadata
identity check records only HTTP status and the `Metadata-Flavor` response
header. It does not read or return an identity, scope list, token, environment
value, path, command line, or file contents.

There is no shell, arbitrary command interpreter, destination supplied by the
plan, network scan, credential use, retained file, or persistence mechanism.
Changing the plan can select a different subset of the seven compiled probes;
it cannot introduce a new operation.

This version changes both the Go source and target/config path so an analyzer
must treat it as a fresh package input instead of reusing the earlier result.
