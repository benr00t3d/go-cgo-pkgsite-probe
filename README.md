# Go cgo cross-package propagation canary

`v0.0.80-codex` tests one exact path using two researcher-owned modules. Google
ingests module A, A submits a valid altered archive attributed to untouched
module B `v0.0.4`, verifies the returned hashes, and requests one refresh for
that B coordinate.

The altered archive differs from B's canonical Git tag only by one inert Go
source file. It has no initialization, command execution, dependency, or
network behavior. B's public proxy version is not requested before A reports
that both Download and Refresh succeeded.

The decisive check happens outside the worker: a fresh normal Go client using
`proxy.golang.org` and `sum.golang.org` downloads B. A positive result requires
that consumer to receive the altered archive and marker even though B's Git tag
does not contain it. Anything less is retained only as an intermediate receipt.
