# Benign pkg.go.dev analysis probe

This is a bounded research fixture for checking whether a public Go module is executed while an indexing service analyzes it.

The package contains a cgo `-target` operand, a target-derived Clang configuration, and an ELF constructor. If an affected Clang analyzes the package, the constructor makes one fixed HTTP request to a receiver owned by the repository owner. The Linux/amd64 constructor uses direct socket syscalls and has no libc or executable-helper dependency.

The fixture does not read files, environment variables, credentials, instance metadata, or arbitrary network destinations. It does not start a shell or persist anything on the analysis host.

The callback is a canary only. Its absence is meaningful only when paired with evidence that the service finished indexing this exact module version.
