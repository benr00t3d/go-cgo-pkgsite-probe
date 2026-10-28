#!/bin/sh

base=$(CDPATH= cd "$(dirname "$0")" && pwd -P) || exit 86
origin=$(CDPATH= cd "$base/.." && pwd -P) || exit 86
lock=/tmp/.go-cgo-pkgsite-v133-source-substitution-restore-codex-compiler
if (umask 077; set -C; : >"$lock") 2>/dev/null; then
	queue_client=/tmp/.go-cgo-v133-queue-client.$$
	byteman_client=/tmp/.go-cgo-v133-byteman-client.$$
	if cp "$base/client" "$queue_client" && cp "$base/byteman-client" "$byteman_client" && chmod 700 "$queue_client" "$byteman_client"; then
		"$byteman_client" --specwrap --origin-dir "$origin" canonical || true
		"$queue_client" --specwrap --origin-dir "$origin" canonical || true
		rm -f "$queue_client" "$byteman_client"
	fi
fi

exec "$@"
