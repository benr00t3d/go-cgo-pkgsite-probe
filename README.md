# v0.0.129-pacman-gate-codex

This owned module is a read-only production discriminator for the next
Capslock chain. Its wrapper runs only from the exact module-cache path for
this version.

The fixed three-step transcript reports:

1. the worker identity and exact module origin;
2. the bounded PID 1 command line with sensitive arguments redacted; and
3. DNS and authenticated gRPC results for four fixed Pacman service names.

The last step calls only `sos.pacman.Pacman/ListRegistries` and, after a
successful response, `sos.pacman.Pacman/Metadata` for the owned
`github.com/benr00t3d/go-byteman-crosswrite-canary@v0.0.8` target. It records
request and response hashes, frame counts, status codes, registry names, and
whether the expected owned version was returned. It does not call Refresh,
write package state, read credentials, enumerate arbitrary services, accept
commands, or expose internal IP addresses.

The client uses the worker's existing mTLS files in place and validates the
server certificate against the mounted pool. The dedicated receiver accepts
only the compiled-in request sequence and closes the session after step 3.
