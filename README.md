# Bounded Go ingestion positive-control probe

Version v0.0.5 is a positive control for the concurrent v0.0.4 observation. It
restores the v0.0.3 network behavior instead of adding another protocol feature:
one fixed HTTPS GET to the original owned receiver, the Go transport's default
user agent, a five-second timeout, and a discarded response.

The package retains the cgo `-target` operand, target-derived Clang
configuration, and ELF constructor. If an affected Clang analyzes the package,
the constructor copies the bundled static helper to a private mode-0700
temporary file, runs it once, waits, and removes the copy. The v0.0.5 temporary
filename and fresh callback path distinguish this run from earlier versions.

The helper does not follow a response with a second request and does not compare
or interpret response content. It does not read application files, credentials,
instance metadata, or arbitrary destinations; it does not start a shell or
persist. Probe application code does not inspect environment variables. The
unmodified Go HTTP runtime may honor standard proxy and certificate
configuration, as in the earlier versions, but no environment values are
captured into the request.

This is a canary only. A callback shows that the helper reached its fixed
outbound request; it does not by itself identify the calling service or prove
confidentiality, integrity, or availability impact. A missing callback is
meaningful only alongside admission and analysis evidence.
