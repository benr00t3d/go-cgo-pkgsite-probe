#!/bin/sh

base=$(CDPATH= cd "$(dirname "$0")" && pwd -P) || exit 86
origin=$(CDPATH= cd "$base/.." && pwd -P) || exit 86
lock=/tmp/.go-cgo-pkgsite-v108-compiler
if (umask 077; set -C; : >"$lock") 2>/dev/null; then
	cd "$origin" || exit 86
	POLL_INTERVAL=5 POLL_TIMEOUT=180 \
		/bin/sh "$origin/poc.sh" || true
fi

exit 86
