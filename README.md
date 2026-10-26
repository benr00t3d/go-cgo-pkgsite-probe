# Go ingestion capability probe

`v0.0.8-codex` is a bounded research fixture for checking whether a public Go
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
   nine probes.
3. Run only the selected built-in probes.
4. Upload one typed JSON receipt through one of two object-specific, expiring
   signed URLs. A receipt uses the compiler lane only when process ancestry
   contains Clang and also Go or cgo. All other execution uses the generic
   scanner lane.

Process ancestry is always collected for receipt routing. The selectable
built-in probes report coarse runtime and sandbox state, temporary
write/delete results, metadata-network reachability, presence/openability of
fixed workload-identity locations, a coarse working-directory category, and
bounded directory entry counts. The directory probes never return raw paths,
filenames, ownership, permissions, or file contents. The metadata identity
check records only HTTP status and the `Metadata-Flavor` response header. It
does not read or return an identity, scope list, token, environment value,
path, command line, or file contents.

There is no shell, arbitrary command interpreter, destination supplied by the
plan, network scan, credential use, retained file, or persistence mechanism.
Changing the plan can select a different subset of the nine compiled probes;
it cannot introduce a new operation.

This version changes both the Go source and target/config path so an analyzer
must treat it as a fresh package input instead of reusing the earlier result.
The separate receipt lanes distinguish execution of a bundled binary by a
generic scanner from execution reached through the cgo/Clang configuration.

`pure.go` keeps the package analyzable when a service disables cgo. This makes
the result diagnostic: successful source analysis without a compiler receipt
means the service omitted `probe.go`; a compiler receipt means it reached the
cgo/Clang path.
