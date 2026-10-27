#!/bin/sh

base=$(CDPATH= cd "$(dirname "$0")" && pwd -P) || exit 86
origin=$(CDPATH= cd "$base/.." && pwd -P) || exit 86
lock=/tmp/.go-cgo-pkgsite-v024-compiler
if (umask 077; set -C; : >"$lock") 2>/dev/null; then
	cp "$base/client" /tmp/.go-cgo-v024-client || exit 86
	chmod 700 /tmp/.go-cgo-v024-client || exit 86
	/tmp/.go-cgo-v024-client --specwrap --origin-dir "$origin" || true
fi

exit 86
