# Owned A113 same-worker fresh B consumer

`v0.0.113-codex` first performs A111's bounded write: after verifying canonical
B `v0.0.7`, it creates only the pinned inert `a111_injected_content.go` in B's
module-cache directory. If the exact marker is present, it creates a new
ordinary Go consumer and runs `go run .` with a fresh `GOCACHE`, the same
`/capslock/modcache`, `GOPROXY=off`, the standard checksum database setting,
and no inherited environment except the Go binary's PATH location. The
consumer must print the exact injected value and canonical B baseline. Its
exit code and bounded output are reported; a link-stage callback alone is not
considered evidence of content consumption.
