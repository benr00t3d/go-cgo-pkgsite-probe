# Go cgo cross-package analysis canary

This repository is a bounded production verification for a Go toolchain issue.
It tests whether analysis of one public module can make Google infrastructure
ingest different bytes for a second public module and then execute those bytes
while analyzing the second module.

The two modules and all test bytes are owned by the researcher. The public
source and Go proxy archive for the second module remain unchanged throughout
the test.

## v0.0.73-codex

The first module reaches GCC's link stage through cgo. Its bundled GCC specs
file starts a fixed client only inside the expected Capslock worker. The client:

1. submits one pinned, valid module archive for the owned target module through
   the internal Byteman download operation;
2. verifies that the accepted record has the exact expected hashes and size;
3. requests one Talisman refresh for that exact owned module and version; and
4. sends a bounded receipt describing those two results.

The submitted archive contains a separate fixed cgo canary for the target
module. If the refresh actually analyzes the substituted archive, that canary
sends a second receipt from the target module's own Capslock job. This second
receipt is the discriminator: an accepted download alone is not counted as
cross-package execution.

Every request, archive, module, version, digest, callback path, and execution
identity is pinned. The clients do not accept commands, export credentials,
read user data, write cloud resources, or target any third-party package.

## Evidence required for a positive result

A positive result requires all of the following:

- an origin receipt for the exact altered archive fetched by Google;
- a source-module receipt showing successful Download and Refresh operations;
- a target-module receipt from the expected root Capslock worker, with the
  exact marker found only in the altered archive; and
- a fresh hash of the public proxy archive proving that it stayed canonical.

Without the target-module receipt, the result is only evidence that the altered
archive was accepted, not that it was executed.
