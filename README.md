# Go public-worker identity canary

`v0.0.75-codex` is a bounded follow-up to an observed automatic execution of
the cgo link-stage gadget in a uid-1000 Ubuntu microVM after public module
discovery.

The bundled client runs only when the module path, version, uid, gid, hostname,
PID 1, and module-cache path match that exact worker shape. It reads three fixed,
non-secret GCE metadata values: project ID, default service-account email, and
OAuth scope names. It then sends one structured receipt.

The client never requests a metadata token, never calls a cloud API, accepts no
commands, and reads no workload or user data. If the exact worker identity does
not match, it exits without making any request.
