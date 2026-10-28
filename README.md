# Talisman result-action descriptor recovery

`v0.0.107-codex` is a bounded read-only follow-up to the successful owned
Queue.Push cross-package result write. It runs only from this version's exact
Capslock modcache directory, reads the already-running `/proc/1/exe`, and
extracts only protobuf file descriptors whose structured summaries contain
`talisman`.

The purpose is to identify the exact result-action type and fields that can
connect the previously ingested altered archive for Robert's owned module B to
B's analysis pipeline. The successful v0.0.62 experiment established that
`sos.queue.Queue/Push` is the cross-package write path; Talisman Refresh alone
did not propagate altered module content.

This probe does not call Queue, Talisman, Pacman, Byteman, Kubernetes, metadata,
or any cloud API. It has no command or arbitrary-path interface. It sends one
bounded descriptor receipt to the fixed research callback. Generic builds stop
before reading the worker binary or making a network request.
