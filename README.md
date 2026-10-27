# Owned-B cross-job Byteman persistence verifier

`v0.0.104-codex` is a bounded follow-up to the `v0.0.68-codex` owned-content
ingestion test. The earlier job issued one `sos.byteman.Byteman/Download` with
policy `ALWAYS=4` for an altered archive of Robert's second owned module.

This version runs only in the exact Capslock modcache origin. It sends one
descriptor-pinned `Download` request for the same URL and metadata with policy
`NEVER=1` and redirect policy `FOLLOW_NONE=2`. The prior one-shot URL is offline,
so the request cannot refetch or rewrite content. A successful exact response
therefore shows that a distinct worker can retrieve the prior altered-B cache
record, including its size and SHA-512/SHA-256/SHA-1/MD5 digests.

The verifier has no command interface and performs no Lookup, Stream, Queue,
Talisman, Pacman, cloud-data, Kubernetes, arbitrary-path, or arbitrary-target
action. Generic builds stop before the internal request or callback. The wrapper
exits with status 86 after the verifier returns so analysis remains observable.
