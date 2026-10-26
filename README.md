# Bounded Go ingestion round-trip probe

This research fixture checks whether a public Go module is executed while an
indexing service analyzes it. Version v0.0.4 adds a fixed two-phase network
round trip and a probe-specific static user agent; it does not add a command
channel.

The package contains a cgo `-target` operand, a target-derived Clang
configuration, and an ELF constructor. If an affected Clang analyzes the
package, the constructor copies the bundled static helper to a private
mode-0700 temporary file, runs it once, waits, and removes the copy.

The helper performs these bounded steps:

1. Send one fixed HTTPS challenge request with a build-time static user agent.
2. Read at most 4097 bytes, require HTTP 200, and compare the body with one
   fixed build-time receipt using a constant-time byte comparison.
3. Only after an exact match, send one fixed HTTPS acknowledgement request.

Redirects are not followed. Both URLs, the receipt, and the user agent are fixed
when the helper is built. The response is never evaluated, executed, used as a
command, or used to select a destination. The acknowledgement contains no
response contents or host-derived data.

The constructor reads only its own path and bundled helper. The helper does not
read application files, credentials, instance metadata, or arbitrary
destinations; it does not start a shell or persist. Probe application code does
not inspect environment variables. The unmodified Go HTTP runtime may honor
standard proxy and certificate configuration, as in v0.0.3, but no environment
values are captured into the probe's requests.

The callbacks are canaries only. Their absence is meaningful only when paired
with evidence that the service analyzed this exact module version. Network
range attribution alone does not identify the calling service or project.
