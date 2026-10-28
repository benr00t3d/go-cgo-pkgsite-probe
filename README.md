# v0.0.122-codex production discriminator

This owned module version distinguishes the Capslock compiler lane from the
open-source `pkgsite-metrics` worker model. Its GCC LTO/sysroot wrapper runs
only from the exact Capslock module path for `v0.0.122-codex`.

The wrapper opens one short session with a dedicated receiver in the owned
`s0victim-44547` project. The receiver can select only compiled-in typed
probes. This in-process typed dispatcher is the `safe_exec` equivalent: it has
no shell, subprocess, or arbitrary code interface. Sessions are serial per pod
fingerprint, run for at most 10 minutes, permit 5 fixed recovery requests plus
at most 30 operator-selected typed follow-ups, and bind every completed request
and result into a rolling transcript hash.

The available probes report:

- lane, UID/GID, hostname, current directory, PID 1, namespaces, and process
  names;
- fixed path and mount metadata for Capslock, worker-layout, and TLS mounts;
- toolchain presence, interface names/flags, and DNS configuration presence;
- bounded PID 1 command-line metadata with sensitive-value redaction, self and
  PID 1 capability/Seccomp/NoNewPrivs fields, and cgroup/container hints;
- names, modes, sizes, and readability only for common projected service
  account roots and the exact `/etc/tls/client` and `/etc/tls/server-pool`
  mounts; file contents and hashes are never read;
- protobuf service and method names only for `sos.talisman`, `sos.queue`,
  `sos.byteman`, and `sos.pacman`, extracted from a bounded read-only mapping of
  the already-running PID 1 executable without invoking any service;
- `lstat`-style metadata for one normalized absolute path, without reading
  file contents or following the final symlink;
- at most 64 names and metadata records from a normalized directory beneath
  an architecture prefix, opened without following the final symlink;
- a create, fsync, unlink, and cleanup-confirmation canary only in `/tmp` or
  the exact current per-job workspace.

Path requests reject relative or non-canonical paths, traversal, NUL bytes,
dangerous proc handle/memory paths, and overlong input. Directory requests are
limited to `/capslock`, `/tmp`, `/proc/self`, `/proc/1`, `/usr/local/go`,
`/app`, and `/bundle`; TLS directories cannot be listed by dynamic requests.
Dynamic process requests accept only a canonical numeric PID and return fixed
process/security metadata, never environment, memory, or file descriptors.
Probe errors are
reported as fixed error codes and do not terminate the session.

The probe does not read credential contents, query metadata or internal
services, expose environment variables, accept commands, make durable writes,
or install persistence. The wrapper uses only an ephemeral
`/tmp` one-shot lock and temporary client copy, then continues the original
compiler command. Separate pods may each create one bounded session.

A completed transcript proves only that this exact compiler-wrapper process
could reach the pinned HTTPS receiver. It does not establish equivalence with
the separate open-source `pkgsite-metrics` gVisor sandbox.
