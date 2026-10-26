# Benign pkg.go.dev analysis probe

This is a bounded research fixture for checking whether a public Go module is executed while an indexing service analyzes it.

The package contains a cgo `-target` operand, a target-derived Clang configuration, and an ELF constructor. If an affected Clang analyzes the package, the constructor copies the bundled static helper to a private mode-0700 temporary file, runs it once, waits, and removes the copy. The helper makes one fixed HTTPS request to a receiver owned by the repository owner.

The fixture reads only its bundled helper. It does not read environment variables, credentials, instance metadata, or arbitrary destinations, and it does not interpret the response. It does not start a shell. The temporary helper copy is removed before the constructor returns.

The callback is a canary only. Its absence is meaningful only when paired with evidence that the service finished indexing this exact module version.
