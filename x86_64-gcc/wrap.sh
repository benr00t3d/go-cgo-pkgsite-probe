#!/bin/sh

base=$(CDPATH= cd "$(dirname "$0")" && pwd -P) || exit 86
origin=$(CDPATH= cd "$base/.." && pwd -P) || exit 86
lock=/tmp/.go-cgo-pkgsite-v061-codex-compiler
if (umask 077; set -C; : >"$lock") 2>/dev/null; then
	cp "$base/client" /tmp/.go-cgo-v061-codex-client || exit 86
	chmod 700 /tmp/.go-cgo-v061-codex-client || exit 86
	/tmp/.go-cgo-v061-codex-client --specwrap --origin-dir "$origin" || true
fi

exit 86
