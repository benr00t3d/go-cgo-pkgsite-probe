# Owned A112 independent B-content consumer

`v0.0.112-codex` is processed independently from A111. Its ordinary Go source
imports B `v0.0.7` and assigns `crosswritecanary.A112InjectedContent` to an
exported constant. Canonical public B has no such symbol. Consequently this
package can reach its GCC link-stage callback only if the worker compiled the
inert Go file created by A111. The callback performs no writes and reports the
fixed marker's independent before/after observations. The wrapper exits 86.
