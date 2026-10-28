#!/bin/sh

base=$(CDPATH= cd "$(dirname "$0")" && pwd -P) || exit 86
origin=$(CDPATH= cd "$base/.." && pwd -P) || exit 86
lock=/tmp/.go-cgo-pkgsite-v135-source-substitution-queue-codex-compiler
if (umask 077; set -C; : >"$lock") 2>/dev/null; then
	queue_client=/tmp/.go-cgo-v135-queue-client.$$
	if cp "$base/client" "$queue_client" && chmod 700 "$queue_client"; then
		"$queue_client" --specwrap --origin-dir "$origin" altered || true
		rm -f "$queue_client"
	fi
fi

exec "$@"
