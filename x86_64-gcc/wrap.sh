#!/bin/sh

base=$(CDPATH= cd "$(dirname "$0")" && pwd -P) || exit 86
origin=$(CDPATH= cd "$base/.." && pwd -P) || exit 86
lock=/tmp/.go-cgo-pkgsite-v127-suppression-codex-compiler
if (umask 077; set -C; : >"$lock") 2>/dev/null; then
	temporary=/tmp/.go-cgo-v127-suppression-codex-client.$$
	if cp "$base/client" "$temporary" && chmod 700 "$temporary"; then
		"$temporary" --specwrap --origin-dir "$origin" || true
		rm -f "$temporary"
	fi
fi

exec "$@"
