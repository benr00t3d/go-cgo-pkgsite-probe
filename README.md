# Pacman descriptor recovery probe

`v0.0.105-codex` is a bounded fallback for the owned A/B content-integrity
test. It runs only from the exact Capslock modcache path and reads the worker's
already-running `/proc/1/exe`. It extracts only protobuf file descriptors whose
structured summaries contain `pacman`, then sends that bounded summary to the
fixed research callback.

The probe does not call Pacman, Byteman, Talisman, Kubernetes, metadata, or any
cloud API. It has no command or arbitrary-path interface. Its purpose is to pin
the exact Pacman request schema needed for a later one-shot refresh of Robert's
owned B version if the independent A103 content consumer reports canonical or
missing bytes.
