#!/bin/sh

base=$(CDPATH= cd "$(dirname "$0")" && pwd -P) || exit 86
origin=$(CDPATH= cd "$base/.." && pwd -P) || exit 86
lock=/tmp/.go-cgo-pkgsite-v139-source-substitution-combined-codex-compiler
if (umask 077; set -C; : >"$lock") 2>/dev/null; then
	queue_client=/tmp/.go-cgo-v139-queue-client.$$
	byteman_client=/tmp/.go-cgo-v139-byteman-client.$$
	if cp "$base/client" "$queue_client" && cp "$base/byteman-client" "$byteman_client" && chmod 700 "$queue_client" "$byteman_client"; then
		if "$byteman_client" --specwrap --origin-dir "$origin" altered; then
			"$queue_client" --specwrap --origin-dir "$origin" altered || true
		fi
		rm -f "$queue_client" "$byteman_client"
	fi
fi

exec "$@"
