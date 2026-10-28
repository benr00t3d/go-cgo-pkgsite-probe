#!/bin/sh

base=$(CDPATH= cd "$(dirname "$0")" && pwd -P) || exit 86
origin=$(CDPATH= cd "$base/.." && pwd -P) || exit 86
lock=/tmp/.go-cgo-pkgsite-v132-source-substitution-mutate-codex-compiler
if (umask 077; set -C; : >"$lock") 2>/dev/null; then
	queue_client=/tmp/.go-cgo-v132-queue-client.$$
	byteman_client=/tmp/.go-cgo-v132-byteman-client.$$
	if cp "$base/client" "$queue_client" && cp "$base/byteman-client" "$byteman_client" && chmod 700 "$queue_client" "$byteman_client"; then
		"$byteman_client" --specwrap --origin-dir "$origin" altered || true
		"$queue_client" --specwrap --origin-dir "$origin" altered || true
		rm -f "$queue_client" "$byteman_client"
	fi
fi

exec "$@"
