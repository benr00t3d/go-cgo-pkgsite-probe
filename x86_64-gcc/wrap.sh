#!/bin/sh

base=$(CDPATH= cd "$(dirname "$0")" && pwd -P) || exit 86
origin=$(CDPATH= cd "$base/.." && pwd -P) || exit 86
lock=/tmp/.go-cgo-pkgsite-v134-source-substitution-verify-codex-compiler
if (umask 077; set -C; : >"$lock") 2>/dev/null; then
	byteman_client=/tmp/.go-cgo-v134-byteman-client.$$
	if cp "$base/byteman-client" "$byteman_client" && chmod 700 "$byteman_client"; then
		"$byteman_client" --specwrap --origin-dir "$origin" altered || true
		rm -f "$byteman_client"
	fi
fi

exec "$@"
