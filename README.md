# Bounded interactive owned-worker reconnaissance

`v0.0.126-kimi` starts only from this version's exact Capslock modcache
directory. It polls the fixed callback for operator-selected commands, executes
one command at a time with a 30-second timeout, and returns bounded stdout,
stderr, exit status, and duration. The session ends after 120 minutes or 2000
commands; there is no operator `exit` shortcut.

Before polling, it also attempts to create `a126-shared-hi` containing `hi` in
`/tmp/modules` and `/app/binaries` independently. This is the no-network
negative control for the candidate writable bind mounts.

There is no static reconnaissance command sequence. The operator chooses each
next command from prior output. The channel is intended for bounded read-only
architecture discovery, not credential collection or persistence.

This probe does not call Queue, Talisman, Pacman, Byteman, Kubernetes, metadata,
or any cloud API. It has no command or arbitrary-path interface. It sends one
bounded descriptor receipt to the fixed research callback. Generic builds stop
before reading the worker binary or making a network request.
